//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

const rabbitMQMigrationEvents = 16

type rabbitMQMigrationPlan struct {
	JobID             string `json:"job_id"`
	RequestID         string `json:"request_id"`
	ActorID           string `json:"actor_id"`
	ProjectID         string `json:"project_id"`
	OriginalContainer string `json:"original_container"`
	SourceSHA         string `json:"source_sha256"`
	OriginalConfigSHA string `json:"original_config_sha256"`
	OriginalMetaSHA   string `json:"original_metadata_sha256"`
	TargetManifestSHA string `json:"target_manifest_sha256"`
	OriginalVolume    string `json:"original_volume"`
	CandidateVolume   string `json:"candidate_volume"`
}

type rabbitMQMigrationEvent struct {
	Sequence    int                    `json:"sequence"`
	PlanSHA     string                 `json:"plan_sha256"`
	PreviousSHA string                 `json:"previous_sha256,omitempty"`
	Phase       string                 `json:"phase"`
	VolumeCopy  rabbitMQColdCopyResult `json:"volume_copy,omitempty"`
}

var rabbitMQMigrationDigest = regexp.MustCompile("^[a-f0-9]{64}$")

func (p rabbitMQMigrationPlan) valid() bool {
	return core.ValidID(p.JobID) && core.ValidID(p.RequestID) && core.ValidID(p.ActorID) && core.ValidID(p.ProjectID) &&
		core.ValidDockerContainerID(p.OriginalContainer) && rabbitMQMigrationDigest.MatchString(p.SourceSHA) && rabbitMQMigrationDigest.MatchString(p.OriginalConfigSHA) &&
		rabbitMQMigrationDigest.MatchString(p.OriginalMetaSHA) && rabbitMQMigrationDigest.MatchString(p.TargetManifestSHA) &&
		p.OriginalVolume == "panel_"+p.ProjectID[:12]+"_data" && p.CandidateVolume == rabbitMQMigrationVolumePrefix+p.JobID
}

func rabbitMQMigrationTransition(from, to string) bool {
	switch from {
	case "":
		return to == "prepared"
	case "prepared":
		return to == "quiesce-intent" || to == "cancelled-before-stop"
	case "quiesce-intent":
		return to == "stop-original-intent" || to == "resume-listeners-intent"
	case "resume-listeners-intent":
		return to == "original-restored"
	case "stop-original-intent":
		return to == "original-stopped" || to == "restore-original-intent"
	case "original-stopped":
		return to == "copy-intent" || to == "restore-original-intent"
	case "copy-intent":
		return to == "copy-verified" || to == "restore-original-intent"
	case "copy-verified":
		return to == "bridge-intent" || to == "restore-original-intent"
	case "bridge-intent":
		return to == "bridge-stopped" || to == "restore-original-intent"
	case "bridge-stopped":
		return to == "target-check-intent" || to == "restore-original-intent"
	case "target-check-intent":
		return to == "target-verified-offline" || to == "restore-original-intent"
	case "target-verified-offline":
		return to == "restore-original-intent" || to == "publish-endpoint-intent"
	case "restore-original-intent":
		return to == "restart-original-intent"
	case "restart-original-intent":
		return to == "original-restored"
	case "publish-endpoint-intent":
		// The new endpoint may already have accepted writes. An unknown
		// outcome at or after this stage may only be reconciled in place.
		return to == "target-published"
	}
	return false
}

// The journal binds recovery to one original job and validated private bytes.
// It records decisions. It never grants access to a broker or Docker effects.
func readRabbitMQMigrationJournal(root *os.Root, expected rabbitMQMigrationPlan) (rabbitMQMigrationEvent, error) {
	var last rabbitMQMigrationEvent
	if !expected.valid() {
		return last, errors.New("RabbitMQ 原迁移计划无效")
	}
	raw, err := geoStoreRead(root, "plan.json", 8<<10)
	if err != nil {
		return last, err
	}
	actual, _ := json.Marshal(expected)
	if !bytes.Equal(raw, actual) {
		return last, errors.New("RabbitMQ 原迁移计划身份或内容变化")
	}
	planSHA := core.Hash(string(actual))
	dir, err := root.Open(".")
	if err != nil {
		return last, err
	}
	defer dir.Close()
	items, err := dir.ReadDir(rabbitMQMigrationEvents + 2)
	if err != nil && !errors.Is(err, io.EOF) || len(items) < 2 || len(items) > rabbitMQMigrationEvents+1 {
		return last, errors.New("RabbitMQ 原迁移事件数量无效")
	}
	names := make(map[string]bool, len(items))
	for _, item := range items {
		names[item.Name()] = true
	}
	var previousSHA string
	for i := 0; i < len(items)-1; i++ {
		name := fmt.Sprintf("event-%02d.json", i)
		if !names[name] {
			return rabbitMQMigrationEvent{}, errors.New("RabbitMQ 原迁移事件缺失或目录含未知内容")
		}
		raw, err := geoStoreRead(root, name, 8<<10)
		if err != nil {
			return rabbitMQMigrationEvent{}, err
		}
		var record rabbitMQMigrationEvent
		if json.Unmarshal(raw, &record) != nil || record.Sequence != i || record.PlanSHA != planSHA ||
			record.PreviousSHA != previousSHA || !validRabbitMQMigrationEvent(last, record) {
			return rabbitMQMigrationEvent{}, errors.New("RabbitMQ 原迁移事件顺序、摘要或证据无效")
		}
		canonical, _ := json.Marshal(record)
		if !bytes.Equal(canonical, raw) {
			return rabbitMQMigrationEvent{}, errors.New("RabbitMQ 原迁移记录字段异常")
		}
		last, previousSHA = record, core.Hash(string(raw))
	}
	return last, nil
}

func validRabbitMQMigrationEvent(last, next rabbitMQMigrationEvent) bool {
	if !rabbitMQMigrationTransition(last.Phase, next.Phase) {
		return false
	}
	if next.Phase == "copy-verified" {
		copy := next.VolumeCopy
		return copy.Files > 0 && copy.Directories > 0 && copy.Bytes > 0 && rabbitMQMigrationDigest.MatchString(copy.SHA256)
	}
	return next.VolumeCopy == last.VolumeCopy
}

func prepareRabbitMQMigrationJournal(root *os.Root, plan rabbitMQMigrationPlan) (rabbitMQMigrationEvent, error) {
	var empty rabbitMQMigrationEvent
	if !plan.valid() {
		return empty, errors.New("RabbitMQ 原迁移计划无效")
	}
	raw, _ := json.Marshal(plan)
	if err := writeRabbitMQMigrationRecord(root, "plan.json", raw); err != nil {
		return empty, err
	}
	first := rabbitMQMigrationEvent{PlanSHA: core.Hash(string(raw)), Phase: "prepared"}
	raw, _ = json.Marshal(first)
	if err := writeRabbitMQMigrationRecord(root, "event-00.json", raw); err != nil {
		return empty, err
	}
	return readRabbitMQMigrationJournal(root, plan)
}

// Advance under the job's exclusive execution lease, after independently
// checking that the actual Docker state agrees with the retained evidence.
func appendRabbitMQMigrationEvent(root *os.Root, plan rabbitMQMigrationPlan, before rabbitMQMigrationEvent,
	phase string, copy rabbitMQColdCopyResult) (rabbitMQMigrationEvent, error) {
	var empty rabbitMQMigrationEvent
	current, err := readRabbitMQMigrationJournal(root, plan)
	if err != nil || current != before {
		return empty, errors.New("RabbitMQ 原迁移事件已变化")
	}
	raw, _ := json.Marshal(current)
	next := rabbitMQMigrationEvent{
		Sequence: current.Sequence + 1, PlanSHA: current.PlanSHA, PreviousSHA: core.Hash(string(raw)),
		Phase: phase, VolumeCopy: copy,
	}
	if next.Sequence >= rabbitMQMigrationEvents || !validRabbitMQMigrationEvent(current, next) {
		return empty, errors.New("RabbitMQ 原迁移阶段不允许此操作")
	}
	raw, _ = json.Marshal(next)
	name := fmt.Sprintf("event-%02d.json", next.Sequence)
	if err := writeRabbitMQMigrationRecord(root, name, raw); err != nil {
		return empty, err
	}
	observed, err := readRabbitMQMigrationJournal(root, plan)
	if err != nil || observed != next {
		return empty, errors.New("RabbitMQ 迁移阶段写入后无法核对，保留原事件")
	}
	return observed, nil
}

// An interrupted write cannot leave the next numbered event half-visible.
// Sync the private inode, publish it without replacing any existing record,
// then sync the directory before an operation can rely on the event.
func writeRabbitMQMigrationRecord(root *os.Root, name string, data []byte) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return errors.New("RabbitMQ 迁移记录未完整写入")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Linkat(fd, "", int(dir.Fd()), name, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	return dir.Sync()
}
