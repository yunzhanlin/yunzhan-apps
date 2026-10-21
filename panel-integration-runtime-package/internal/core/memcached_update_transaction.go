package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"local/panel/internal/appcatalog"
)

const MaxMemcachedUpdateRecordBytes = 16 << 10
const MaxMemcachedUpdateInputBytes = 2048
const MemcachedUpdateJournalEvents = 16
const MaxMemcachedUpdateChainBytes = MaxMemcachedUpdateRecordBytes * MemcachedUpdateJournalEvents

// These fields bind one deliberate cache-recreating update to the exact old
// project inspection. Paths, images, ports, commands and public keys are never
// accepted as update instructions. Actor/job/request IDs are assigned or taken
// from authenticated context by Core, not borrowed from a browser body.
type MemcachedUpdateInput struct {
	ExpectedVersion       string `json:"expected_version"`
	ExpectedSHA256        string `json:"expected_sha256"`
	ExpectedProjectSHA256 string `json:"expected_project_sha256"`
	AcknowledgeCacheLoss  bool   `json:"acknowledge_cache_loss"`
}

type MemcachedUpdateDispatch struct {
	Format         int                  `json:"format"`
	JobID          string               `json:"job_id"`
	RequestID      string               `json:"request_id"`
	ActorID        string               `json:"actor_id"`
	AccessRevision string               `json:"access_revision"`
	ProjectID      string               `json:"project_id"`
	Input          MemcachedUpdateInput `json:"input"`
}

func DecodeMemcachedUpdateInput(raw []byte) (MemcachedUpdateInput, error) {
	var out MemcachedUpdateInput
	bad := errors.New("Memcached 更新输入必须为完整、无重复字段的固定版本、摘要和缓存清空确认")
	if len(raw) == 0 || len(raw) > MaxMemcachedUpdateInputBytes {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return out, bad
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return MemcachedUpdateInput{}, bad
		}
		seen[name] = true
		switch name {
		case "expected_version":
			err = d.Decode(&out.ExpectedVersion)
		case "expected_sha256":
			err = d.Decode(&out.ExpectedSHA256)
		case "expected_project_sha256":
			err = d.Decode(&out.ExpectedProjectSHA256)
		case "acknowledge_cache_loss":
			err = d.Decode(&out.AcknowledgeCacheLoss)
		default:
			return MemcachedUpdateInput{}, bad
		}
		if err != nil {
			return MemcachedUpdateInput{}, bad
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 4 || out.ExpectedVersion != appcatalog.MemcachedDigestVersion ||
		!registryDigestValid(out.ExpectedSHA256) || !registryDigestValid(out.ExpectedProjectSHA256) || !out.AcknowledgeCacheLoss {
		return MemcachedUpdateInput{}, bad
	}
	if _, err := d.Token(); err != io.EOF {
		return MemcachedUpdateInput{}, bad
	}
	return out, nil
}

func ValidateMemcachedUpdateDispatch(in MemcachedUpdateDispatch) error {
	revision, err := strconv.ParseInt(in.AccessRevision, 10, 64)
	if in.Format != 1 || !ValidID(in.JobID) || !ValidID(in.RequestID) || !ValidID(in.ActorID) || !ValidID(in.ProjectID) ||
		err != nil || revision < 1 || strconv.FormatInt(revision, 10) != in.AccessRevision ||
		in.Input.ExpectedVersion != appcatalog.MemcachedDigestVersion || !registryDigestValid(in.Input.ExpectedSHA256) ||
		!registryDigestValid(in.Input.ExpectedProjectSHA256) || !in.Input.AcknowledgeCacheLoss {
		return errors.New("Memcached 更新必须绑定原项目、当前用户、固定应用版本与摘要，并明确接受缓存可能清空")
	}
	return nil
}

func MemcachedUpdateDispatchSHA(in MemcachedUpdateDispatch) string {
	if ValidateMemcachedUpdateDispatch(in) != nil {
		return ""
	}
	raw, _ := json.Marshal(struct {
		Domain   string                  `json:"domain"`
		Dispatch MemcachedUpdateDispatch `json:"dispatch"`
	}{"yunzhan.memcached-update-dispatch.v1", in})
	return Hash(string(raw))
}

type MemcachedUpdateObservation struct {
	ContainerID         string `json:"container_id"`
	ImageID             string `json:"image_id"`
	ComposeSHA256       string `json:"compose_sha256"`
	RuntimeConfigSHA256 string `json:"runtime_config_sha256"`
	Health              string `json:"health"`
}

// A canonical hash-chained private record is evidence of transaction progress,
// NOT signing authority or proof by itself that Docker was inspected. Root
// must independently verify the envelope, held original files, actual daemon
// state and healthy observations before performing the associated transitions.
// It contains no YAML, credentials, environment or raw Docker inspection.
type MemcachedUpdateRecord struct {
	Format              int                        `json:"format"`
	Dispatch            MemcachedUpdateDispatch    `json:"dispatch"`
	DispatchSHA256      string                     `json:"dispatch_sha256"`
	Plan                MemcachedUpdatePlan        `json:"plan"`
	EnvelopeSHA256      string                     `json:"envelope_sha256"`
	CatalogSHA256       string                     `json:"catalog_sha256"`
	TargetComposeSHA256 string                     `json:"target_compose_sha256"`
	Sequence            int                        `json:"sequence"`
	Phase               string                     `json:"phase"`
	PreviousSHA256      string                     `json:"previous_sha256"`
	TargetImageID       string                     `json:"target_image_id"`
	Observation         MemcachedUpdateObservation `json:"observation"`
	Reason              string                     `json:"reason"`
	RecordSHA256        string                     `json:"record_sha256"`
}

func memcachedLocalImageID(value string) bool {
	return strings.HasPrefix(value, "sha256:") && registryDigestValid(strings.TrimPrefix(value, "sha256:"))
}

func memcachedRecordSHA(in MemcachedUpdateRecord) string {
	in.RecordSHA256 = ""
	raw, err := json.Marshal(struct {
		Domain string                `json:"domain"`
		Record MemcachedUpdateRecord `json:"record"`
	}{"yunzhan.memcached-update-record.v1", in})
	if err != nil {
		return ""
	}
	return Hash(string(raw))
}

// Seal is deterministic framing only. It cannot make a fabricated record an
// authenticated receipt, authorize a job, or turn an observation into a retry.
func SealMemcachedUpdateRecord(in MemcachedUpdateRecord) (MemcachedUpdateRecord, error) {
	in.RecordSHA256 = memcachedRecordSHA(in)
	if err := ValidateMemcachedUpdateRecord(in); err != nil {
		return MemcachedUpdateRecord{}, err
	}
	return in, nil
}

func ValidateMemcachedUpdateRecord(in MemcachedUpdateRecord) error {
	bad := errors.New("Memcached 原事务记录、阶段或摘要绑定无法核对；未提交、覆盖或重放")
	if in.Format != 1 || ValidateMemcachedUpdateDispatch(in.Dispatch) != nil || in.DispatchSHA256 != MemcachedUpdateDispatchSHA(in.Dispatch) ||
		ValidateMemcachedUpdatePlan(in.Plan, in.Dispatch.ProjectID) != nil || in.Plan.ProjectSHA256 != in.Dispatch.Input.ExpectedProjectSHA256 ||
		in.Plan.AlreadyPinned || in.Plan.CurrentImage != "memcached:1.6.45-alpine" || !registryDigestValid(in.EnvelopeSHA256) || !registryDigestValid(in.CatalogSHA256) ||
		in.Sequence < 0 || in.Sequence >= MemcachedUpdateJournalEvents || !registryDigestValid(in.RecordSHA256) || in.RecordSHA256 != memcachedRecordSHA(in) {
		return bad
	}
	target, err := dockerTemplate("memcached-cache", in.Plan.HostPort)
	if err != nil || in.TargetComposeSHA256 != Hash(target) || in.TargetComposeSHA256 == in.Plan.ComposeSHA256 {
		return bad
	}
	if in.Sequence == 0 {
		if in.Phase != "prepared" || in.PreviousSHA256 != "" {
			return bad
		}
	} else if in.Phase == "prepared" || !registryDigestValid(in.PreviousSHA256) || in.PreviousSHA256 == in.RecordSHA256 {
		return bad
	}
	zero := in.Observation == (MemcachedUpdateObservation{})
	observed := !zero && registryDigestValid(in.Observation.ContainerID) && memcachedLocalImageID(in.Observation.ImageID) &&
		registryDigestValid(in.Observation.ComposeSHA256) && registryDigestValid(in.Observation.RuntimeConfigSHA256) && in.Observation.Health == "healthy"
	targetObserved := observed && in.Observation.ImageID == in.TargetImageID && in.Observation.ComposeSHA256 == in.TargetComposeSHA256
	oldObserved := observed && in.Observation.ImageID == in.Plan.RuntimeImageID && in.Observation.ComposeSHA256 == in.Plan.RollbackComposeSHA256
	image := in.TargetImageID != ""
	if image && !memcachedLocalImageID(in.TargetImageID) {
		return bad
	}
	switch in.Phase {
	case "prepared", "pull_started":
		if image || !zero || in.Reason != "" || in.Phase == "pull_started" && in.Sequence != 1 {
			return bad
		}
	case "image_verified", "apply_started":
		if !image || !zero || in.Reason != "" || in.Phase == "image_verified" && in.Sequence != 2 || in.Phase == "apply_started" && in.Sequence != 3 {
			return bad
		}
	case "applied", "committed":
		if !image || !targetObserved || in.Reason != "" || in.Phase == "applied" && in.Sequence != 4 || in.Phase == "committed" && in.Sequence != 5 {
			return bad
		}
	case "failed_safe":
		if !zero || in.Sequence < 1 || in.Sequence > 3 || in.Reason != "precondition_changed" && in.Reason != "pull_failed" && in.Reason != "target_image_rejected" && in.Reason != "request_canceled" {
			return bad
		}
	case "rollback_started":
		if !image || in.Sequence != 4 && in.Sequence != 5 || !zero && !targetObserved || in.Reason != "apply_failed" && in.Reason != "target_unhealthy" && in.Reason != "target_identity_mismatch" {
			return bad
		}
	case "rolled_back":
		if !image || in.Sequence != 5 && in.Sequence != 6 || !oldObserved || in.Reason != "apply_failed" && in.Reason != "target_unhealthy" && in.Reason != "target_identity_mismatch" {
			return bad
		}
	case "needs_attention":
		if in.Sequence < 1 || in.Sequence > 6 || !zero && !targetObserved || in.Reason != "interrupted" && in.Reason != "journal_uncertain" && in.Reason != "source_drift" && in.Reason != "apply_unknown" && in.Reason != "rollback_failed" && in.Reason != "health_unknown" {
			return bad
		}
	default:
		return bad
	}
	return nil
}

// Require contiguous immutable progress. No terminal record can be resumed or
// rewritten to hide a failure. In particular interrupted/uncertain application
// phases never return to prepared/pull/apply, even after a process restart.
func ValidateMemcachedUpdateTransition(before, after MemcachedUpdateRecord) error {
	bad := errors.New("Memcached 原事务阶段不允许该变化；保留原证据，不重试未知动作")
	if ValidateMemcachedUpdateRecord(before) != nil || ValidateMemcachedUpdateRecord(after) != nil ||
		after.Sequence != before.Sequence+1 || after.PreviousSHA256 != before.RecordSHA256 ||
		after.Dispatch != before.Dispatch || after.DispatchSHA256 != before.DispatchSHA256 || after.Plan != before.Plan ||
		after.EnvelopeSHA256 != before.EnvelopeSHA256 || after.CatalogSHA256 != before.CatalogSHA256 || after.TargetComposeSHA256 != before.TargetComposeSHA256 {
		return bad
	}
	if before.TargetImageID != "" && after.TargetImageID != before.TargetImageID ||
		before.TargetImageID == "" && after.TargetImageID != "" && (before.Phase != "pull_started" || after.Phase != "image_verified") {
		return bad
	}
	allowed := false
	switch before.Phase {
	case "prepared":
		allowed = after.Phase == "pull_started" || after.Phase == "failed_safe" || after.Phase == "needs_attention"
	case "pull_started":
		allowed = after.Phase == "image_verified" || after.Phase == "failed_safe" || after.Phase == "needs_attention"
	case "image_verified":
		allowed = after.Phase == "apply_started" || after.Phase == "failed_safe" || after.Phase == "needs_attention"
	case "apply_started":
		allowed = after.Phase == "applied" || after.Phase == "rollback_started" || after.Phase == "needs_attention"
	case "applied":
		allowed = after.Phase == "committed" || after.Phase == "rollback_started" || after.Phase == "needs_attention"
	case "rollback_started":
		allowed = after.Phase == "rolled_back" || after.Phase == "needs_attention"
	}
	if !allowed {
		return bad
	}
	if after.Phase != "applied" && after.Phase != "rolled_back" && after.Observation != before.Observation {
		return bad
	}
	if after.Phase == "rolled_back" && after.Reason != before.Reason {
		return bad
	}
	if after.Phase == "failed_safe" && before.Phase != "pull_started" && (after.Reason == "pull_failed" || after.Reason == "target_image_rejected") {
		return bad
	}
	return nil
}

// Private journal files have one writer and a canonical encoding. Requiring
// byte-for-byte Marshal output rejects duplicate, case, escaped aliases, null,
// unknown fields and trailing values rather than normalizing tampered files.
func DecodeMemcachedUpdateRecord(raw []byte) (MemcachedUpdateRecord, error) {
	var out MemcachedUpdateRecord
	if len(raw) == 0 || len(raw) > MaxMemcachedUpdateRecordBytes || json.Unmarshal(raw, &out) != nil || ValidateMemcachedUpdateRecord(out) != nil {
		return MemcachedUpdateRecord{}, errors.New("Memcached 原事务记录内容或容量无效")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return MemcachedUpdateRecord{}, errors.New("Memcached 原事务记录编码不规范，未采用歧义内容")
	}
	return out, nil
}

// A status query can skip several polls, but not several evidence events. The
// entire bounded original chain must still bind to the exact reserved seed.
func MemcachedUpdateChainHead(seed MemcachedUpdateRecord, chain []MemcachedUpdateRecord) (MemcachedUpdateRecord, error) {
	bad := errors.New("Memcached 原事务完整事件链与保留请求不一致")
	if ValidateMemcachedUpdateRecord(seed) != nil || seed.Phase != "prepared" || len(chain) == 0 || len(chain) > MemcachedUpdateJournalEvents || chain[0] != seed {
		return MemcachedUpdateRecord{}, bad
	}
	for i, record := range chain {
		if record.Sequence != i || ValidateMemcachedUpdateRecord(record) != nil || i > 0 && ValidateMemcachedUpdateTransition(chain[i-1], record) != nil {
			return MemcachedUpdateRecord{}, bad
		}
	}
	return chain[len(chain)-1], nil
}
