//go:build linux

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const hardeningPendingName = "hardening.pending.json"
const hardeningJournalDirectory = "hardening-transactions"
const hardeningJournalBytes = 256 << 10
const hardeningJournalRecords = 128

var hardeningBootID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// A persisted record cannot choose a path, executable or sysctl name. The three
// files are fixed by their array position; all kernel keys are recomputed from
// the two closed profiles before the plan can become recovery authority.
type hardeningJournalFile struct {
	Exists bool       `json:"exists"`
	Mode   uint32     `json:"mode"`
	Owner  *fileOwner `json:"owner"`
	Data   []byte     `json:"data"`
}

type hardeningJournalChange struct {
	Name   string               `json:"name"`
	Before hardeningJournalFile `json:"before"`
	After  hardeningJournalFile `json:"after"`
}

type hardeningJournalPlan struct {
	Format        int                      `json:"format"`
	ID            string                   `json:"id"`
	Action        string                   `json:"action"`
	StartedAt     string                   `json:"started_at"`
	BootID        string                   `json:"boot_id"`
	FromProfile   string                   `json:"from_profile"`
	ToProfile     string                   `json:"to_profile"`
	TargetVersion string                   `json:"target_version,omitempty"`
	BeforeKernel  map[string]string        `json:"before_kernel"`
	AfterKernel   map[string]string        `json:"after_kernel"`
	Files         []hardeningJournalChange `json:"files"`
}

type hardeningJournalTerminal struct {
	Format        int                  `json:"format"`
	State         string               `json:"state"`
	PlanSHA256    string               `json:"plan_sha256"`
	Plan          hardeningJournalPlan `json:"plan"`
	FinishedAt    string               `json:"finished_at"`
	RecoveryJobID string               `json:"recovery_job_id"`
}

func hardeningJournalEncode(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > hardeningJournalBytes {
		return nil, errors.New("加固事务超过固定私有记录容量")
	}
	return raw, nil
}

func hardeningJournalDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func hardeningCanonicalTime(value string) bool {
	t, err := time.Parse(time.RFC3339, value)
	return err == nil && t.UTC().Format("2006-01-02T15:04:05Z") == value
}

func hardeningJournalStoredFile(file hardeningJournalFile, private bool) error {
	if !file.Exists {
		if file.Mode != 0 || file.Owner != nil || len(file.Data) != 0 {
			return errors.New("不存在的加固文件含不明确的恢复数据")
		}
		return nil
	}
	if file.Owner == nil || file.Owner.UID != uint32(os.Geteuid()) || len(file.Data) < 1 || len(file.Data) > 64<<10 || file.Mode > 0777 || file.Mode&0022 != 0 {
		return errors.New("加固文件恢复数据的容量、归属或权限无效")
	}
	if private && file.Mode != 0600 && (file.Mode != 0640 || file.Owner.GID != uint32(os.Getegid())) {
		return errors.New("加固私有清单恢复权限无效")
	}
	return nil
}

func hardeningJournalFromBackup(backup fileBackup) hardeningJournalFile {
	if !backup.existed {
		return hardeningJournalFile{}
	}
	owner := *backup.owner
	return hardeningJournalFile{true, uint32(backup.mode.Perm()), &owner, bytes.Clone(backup.data)}
}

func (file hardeningJournalFile) backup(path string) fileBackup {
	return fileBackup{path: path, existed: file.Exists, mode: os.FileMode(file.Mode), owner: file.Owner, data: bytes.Clone(file.Data)}
}

func hardeningJournalManifest(file hardeningJournalFile) (softwareManifest, error) {
	var manifest softwareManifest
	if !file.Exists {
		return manifest, nil
	}
	fields := map[string]bool{"id": true, "version": true, "settings": true, "previous": true, "installed_at": true}
	if decodeApacheWAFPrivateJSON(file.Data, &manifest, fields, 100000) != nil || manifest.ID != "system-hardening" || !hardeningCanonicalTime(manifest.InstalledAt) {
		return manifest, errors.New("加固事务原清单不能作为恢复身份")
	}
	comparison, valid := appcatalog.CompareVersions(manifest.Version, core.SoftwareImplementationVersion("system-hardening"))
	if !valid || comparison > 0 {
		return manifest, errors.New("加固事务原版本不受当前处理器支持")
	}
	if _, err := hardeningPrevious(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

// Build the AFTER state from the captured BEFORE state, not caller-supplied
// target bytes. This same derivation validates persisted records after restart.
func hardeningJournalDerive(plan hardeningJournalPlan) (hardeningJournalPlan, error) {
	// Derivation must not rewrite the caller's stored AFTER authority before
	// comparison. A struct copy alone still aliases the slice backing array.
	plan.Files = slices.Clone(plan.Files)
	if plan.Format != 1 || !core.ValidID(plan.ID) || !hardeningCanonicalTime(plan.StartedAt) || !hardeningBootID.MatchString(plan.BootID) || len(plan.Files) != 3 {
		return plan, errors.New("加固事务格式、原任务身份或时间无效")
	}
	for i, name := range []string{"current", "legacy", "manifest"} {
		if plan.Files[i].Name != name {
			return plan, errors.New("加固事务文件范围不固定")
		}
		if err := hardeningJournalStoredFile(plan.Files[i].Before, i == 2); err != nil {
			return plan, err
		}
	}
	old, err := hardeningJournalManifest(plan.Files[2].Before)
	if err != nil {
		return plan, err
	}
	installed := plan.Files[2].Before.Exists
	if plan.Action != "install" && plan.Action != "configure" && plan.Action != "uninstall" && plan.Action != "update" {
		return plan, errors.New("加固事务操作无效")
	}
	if installed == (plan.Action == "install") {
		return plan, errors.New("加固事务操作与原安装身份冲突")
	}
	from := ""
	oldKeys := map[string]string{}
	originals := map[string]string{}
	if installed {
		from, _ = hardeningProfile(old.Settings)
		oldKeys, err = hardeningPrevious(old)
		if err != nil {
			return plan, err
		}
		originals = maps.Clone(old.Previous)
	}
	plan.FromProfile = from
	// Empty target_version is the original format-1 grammar and must keep its
	// exact 1.0 target forever; new code cannot reinterpret archived authority.
	targetVersion := plan.TargetVersion
	if targetVersion == "" {
		targetVersion = "1.0"
	}
	if plan.TargetVersion == "" && installed {
		if comparison, valid := appcatalog.CompareVersions(old.Version, "1.0"); !valid || comparison > 0 {
			return plan, errors.New("原格式1.0日志不能接管较新的安装版本")
		}
	}
	if plan.Action == "update" {
		if !installed || plan.ToProfile != from || plan.TargetVersion != "1.1.0" {
			return plan, errors.New("加固更新必须保留原基线并绑定完整固定目标版本")
		}
		if comparison, valid := appcatalog.CompareVersions(targetVersion, old.Version); !valid || comparison < 0 {
			return plan, errors.New("加固更新不能降级原版本")
		}
	} else if plan.TargetVersion != "" {
		if plan.Action == "install" && targetVersion != "1.1.0" || installed && targetVersion != old.Version {
			return plan, errors.New("普通加固配置不能隐式提升版本或重写原安装能力")
		}
	}
	beforeConfigs := []fileBackup{plan.Files[0].Before.backup("current"), plan.Files[1].Before.backup("legacy")}
	if err = hardeningConfigMatches(beforeConfigs, old, installed); err != nil {
		return plan, err
	}
	newKeys := map[string]string{}
	if plan.Action == "uninstall" {
		if plan.ToProfile != "" {
			return plan, errors.New("移除事务不能指定新基线")
		}
	} else {
		if _, err = hardeningProfile(map[string]any{"profile": plan.ToProfile}); err != nil {
			return plan, err
		}
		newKeys = hardeningValues(plan.ToProfile)
	}
	union := maps.Clone(oldKeys)
	maps.Copy(union, newKeys)
	if len(plan.BeforeKernel) != len(union) {
		return plan, errors.New("加固事务原内核值缺失或超出固定范围")
	}
	for key := range union {
		value, ok := plan.BeforeKernel[key]
		if !ok || !hardeningValueValid(key, value) {
			return plan, errors.New("加固事务原内核值不可核对")
		}
	}
	for key := range newKeys {
		if _, ok := originals[key]; !ok {
			originals[key] = plan.BeforeKernel[key]
		}
	}
	targets := maps.Clone(newKeys)
	for key := range oldKeys {
		if _, keep := newKeys[key]; !keep {
			targets[key] = originals[key]
			delete(originals, key)
		}
	}
	for key, value := range targets {
		if err = hardeningReversible(key, plan.BeforeKernel[key], value); err != nil {
			return plan, err
		}
	}
	plan.AfterKernel = targets
	for i := range plan.Files {
		plan.Files[i].After = hardeningJournalFile{}
	}
	if plan.Action != "uninstall" {
		owner := &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		if plan.Files[0].Before.Exists {
			value := *plan.Files[0].Before.Owner
			owner = &value
		}
		plan.Files[0].After = hardeningJournalFile{true, 0644, owner, []byte(renderSysctl(newKeys))}
		manifest := softwareManifest{ID: "system-hardening", Version: targetVersion, Settings: map[string]any{"profile": plan.ToProfile}, Previous: originals, InstalledAt: plan.StartedAt}
		if installed {
			manifest.InstalledAt = old.InstalledAt
		}
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return plan, err
		}
		data = append(data, '\n')
		owner = &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		if installed {
			value := *plan.Files[2].Before.Owner
			owner = &value
		}
		plan.Files[2].After = hardeningJournalFile{true, 0600, owner, data}
	}
	return plan, nil
}

func hardeningJournalValidate(plan hardeningJournalPlan) error {
	expected, err := hardeningJournalDerive(plan)
	if err != nil {
		return err
	}
	actualRaw, err := hardeningJournalEncode(plan)
	if err != nil {
		return err
	}
	expectedRaw, err := hardeningJournalEncode(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualRaw, expectedRaw) {
		return errors.New("加固事务目标不符合原配置和固定基线推导，未修复记录")
	}
	return nil
}

func hardeningJournalDecode(raw []byte) (hardeningJournalPlan, error) {
	var plan hardeningJournalPlan
	// Apache's decoder assigns its own required transaction/file grammar to
	// a root `format` field. This record has an independent closed schema;
	// retain the existing generic typed duplicate/UTF8/depth checks instead.
	if len(raw) < 1 || len(raw) > hardeningJournalBytes || decodeProgramQueueJSON(raw, &plan) != nil {
		return plan, errors.New("加固事务私有记录损坏、未知或过大")
	}
	if err := hardeningJournalValidate(plan); err != nil {
		return plan, err
	}
	canonical, err := hardeningJournalEncode(plan)
	if err != nil || !bytes.Equal(canonical, raw) {
		return plan, errors.New("加固事务不是原完整规范记录")
	}
	return plan, nil
}

func (s *Service) hardeningJournalPaths() []string {
	return []string{s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf"), s.systemPath("/etc/sysctl.d/90-panel-hardening.conf"), s.softwareManifestPath("system-hardening")}
}

func (s *Service) hardeningJournalRoot() (*os.Root, error) {
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, false); err != nil {
		return nil, err
	}
	return s.softwareManifestDirectory()
}

func (s *Service) hardeningJournalPending() (hardeningJournalPlan, []byte, error) {
	var plan hardeningJournalPlan
	root, err := s.hardeningJournalRoot()
	if err != nil {
		return plan, nil, err
	}
	defer root.Close()
	file, err := hardeningReadBackupLimit(root, hardeningPendingName, filepath.Join(s.Config.SecurityDir, hardeningPendingName), true, hardeningJournalBytes)
	if err != nil {
		return plan, nil, err
	}
	if !file.existed {
		return plan, nil, os.ErrNotExist
	}
	if file.mode != 0600 {
		return plan, nil, errors.New("待恢复加固事务不是0600私有记录")
	}
	plan, err = hardeningJournalDecode(file.data)
	return plan, file.data, err
}

func hardeningJournalSync(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func hardeningJournalTerminalValidate(terminal hardeningJournalTerminal) error {
	if terminal.Format != 1 || (terminal.State != "committed" && terminal.State != "rolled_back") || !hardeningCanonicalTime(terminal.FinishedAt) || (terminal.RecoveryJobID != "" && !core.ValidID(terminal.RecoveryJobID)) {
		return errors.New("加固终态回执格式、状态或恢复任务身份无效")
	}
	if err := hardeningJournalValidate(terminal.Plan); err != nil {
		return err
	}
	raw, err := hardeningJournalEncode(terminal.Plan)
	if err != nil {
		return err
	}
	if hardeningJournalDigest(raw) != terminal.PlanSHA256 {
		return errors.New("加固终态回执与原计划摘要不一致")
	}
	return nil
}

func hardeningJournalTerminalDecode(raw []byte, id string) (hardeningJournalTerminal, error) {
	var terminal hardeningJournalTerminal
	if len(raw) < 1 || len(raw) > hardeningJournalBytes || decodeProgramQueueJSON(raw, &terminal) != nil {
		return terminal, errors.New("加固终态回执损坏或含未知字段")
	}
	if terminal.Plan.ID != id {
		return terminal, errors.New("加固终态回执原任务身份不符")
	}
	if err := hardeningJournalTerminalValidate(terminal); err != nil {
		return terminal, err
	}
	canonical, err := hardeningJournalEncode(terminal)
	if err != nil || !bytes.Equal(canonical, raw) {
		return terminal, errors.New("加固终态不是原完整规范记录")
	}
	return terminal, nil
}

func hardeningJournalError(stage string, err error) error {
	return fmt.Errorf("加固事务%s未完成，保留原记录且未宣称成功: %w", stage, err)
}
