//go:build linux

package executor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"

	"local/panel/internal/core"
)

const intrusionTransactionVersion = "1.1.0"
const intrusionJournalBytes = 256 << 10

// These are identities, not paths, command templates or persisted nft input.
// Recovery must observe the live sets again. Historical IPs in KernelBefore
// are audit evidence only and must never be re-banned or restored from here.
type intrusionManagedPolicy struct {
	Format     int    `json:"format"`
	Action     string `json:"action"`
	Name       string `json:"name"`
	Table      string `json:"table"`
	Chain      string `json:"chain"`
	IPv4Set    string `json:"ipv4_set"`
	IPv6Set    string `json:"ipv6_set"`
	Ports      []int  `json:"ports"`
	MaxMatches int    `json:"max_matches"`
}

type intrusionJournalPlan struct {
	Format                int                        `json:"format"`
	ID                    string                     `json:"id"`
	Action                string                     `json:"action"`
	StartedAt             string                     `json:"started_at"`
	BootID                string                     `json:"boot_id"`
	TargetVersion         string                     `json:"target_version"`
	TargetSettings        map[string]int             `json:"target_settings"`
	InstallBeforeSettings map[string]int             `json:"install_before_settings,omitempty"`
	Removal               *intrusionRemovalEvidence  `json:"removal,omitempty"`
	TargetPorts           []int                      `json:"target_ports"`
	BeforePolicy          intrusionManagedPolicy     `json:"before_policy"`
	KernelState           string                     `json:"kernel_state"`
	KernelBefore          []byte                     `json:"kernel_before"`
	KernelDirectory       []byte                     `json:"kernel_directory"`
	BansBefore            []string                   `json:"bans_before"`
	ConfigurationBefore   intrusionConfigurationTree `json:"configuration_before"`
	ActionBefore          intrusionActionRecipe      `json:"action_before"`
	ProcessBefore         string                     `json:"process_before"`
	ProcessStartBefore    string                     `json:"process_start_before"`
	JournalMatchBefore    string                     `json:"journal_match_before"`
	EffectiveBefore       string                     `json:"effective_before"`
	Files                 []hardeningJournalChange   `json:"files"`
}

func intrusionPolicyValidate(policy intrusionManagedPolicy) error {
	if policy.Format != 1 || policy.Action != "nftables" && policy.Action != "nftables-multiport" {
		return errors.New("入侵防护动作身份或格式未支持安全接管")
	}
	if policy.MaxMatches < 1 || policy.MaxMatches > 1024 {
		return errors.New("入侵防护原匹配容量未知或超限，未随重试次数隐式改变")
	}
	for _, name := range []string{policy.Name, policy.Table, policy.Chain, policy.IPv4Set, policy.IPv6Set} {
		if !intrusionNftWriteName(name) {
			return errors.New("入侵防护内核对象不属于固定安全标识符")
		}
	}
	if policy.IPv4Set == policy.IPv6Set {
		return errors.New("入侵防护地址族集合身份冲突")
	}
	return intrusionJournalPorts(policy.Ports)
}

func intrusionJournalPorts(ports []int) error {
	if len(ports) < 1 || len(ports) > intrusionMaxPorts {
		return errors.New("入侵防护事务端口范围缺失或超限")
	}
	for i, port := range ports {
		if port < 1 || port > 65535 || i > 0 && ports[i-1] >= port {
			return errors.New("入侵防护事务端口范围不是规范数字集合")
		}
	}
	return nil
}

func intrusionJournalSettings(settings map[string]int) (map[string]any, error) {
	out := map[string]any{}
	for name, value := range settings {
		out[name] = value
	}
	_, err := intrusionSettings(out)
	return out, err
}

func intrusionPolicyScope(policy intrusionManagedPolicy, bans []netip.Addr) intrusionNftScope {
	return intrusionNftScope{Table: policy.Table, Chain: policy.Chain, IPv4Set: policy.IPv4Set, IPv6Set: policy.IPv6Set, Ports: slices.Clone(policy.Ports), Banned: slices.Clone(bans)}
}

func intrusionJournalEncode(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > intrusionJournalBytes {
		return nil, errors.New("入侵防护事务超过固定私有容量")
	}
	return raw, nil
}

func intrusionJournalManifest(file hardeningJournalFile) (softwareManifest, error) {
	var manifest softwareManifest
	if !file.Exists || decodeProgramQueueJSON(file.Data, &manifest) != nil || manifest.ID != "intrusion-prevention" || !hardeningCanonicalTime(manifest.InstalledAt) || len(manifest.Previous) != 0 {
		return manifest, errors.New("入侵防护原清单身份、字段或时间不可核对")
	}
	if manifest.Version != "1.0" && manifest.Version != "1.0.0" && manifest.Version != intrusionTransactionVersion {
		return manifest, errors.New("入侵防护原版本未支持本次固定迁移")
	}
	_, err := intrusionSettings(manifest.Settings)
	return manifest, err
}

// An original record cannot choose file paths, executables, reload targets,
// rule statements, timestamps for bans or replacement sets. The three AFTER
// files are always derived again, including when a record is read after crash.
// Installation can adopt an already-running compatible base Jail, with all
// three panel files positively absent and independent actual BEFORE limits.
// It cannot start a disabled service or invent an old installation manifest.
// Removal derives its fixed absent targets ONLY from a complete privately
// observed underlying configuration; it never stops or removes the base Jail.
func intrusionJournalDerive(plan intrusionJournalPlan) (intrusionJournalPlan, error) {
	plan.Files = slices.Clone(plan.Files)
	if plan.Format != 1 || !core.ValidID(plan.ID) || !hardeningCanonicalTime(plan.StartedAt) || !hardeningBootID.MatchString(plan.BootID) || plan.TargetVersion != intrusionTransactionVersion || len(plan.Files) != 3 {
		return plan, errors.New("入侵防护事务格式、原任务或固定目标无效")
	}
	if plan.Action != "configure" && plan.Action != "update" && plan.Action != "install" && plan.Action != "uninstall" {
		return plan, errors.New("入侵防护事务操作未支持安全执行")
	}
	if err := intrusionPolicyValidate(plan.BeforePolicy); err != nil {
		return plan, err
	}
	if _, err := intrusionActionRecipeValidate(intrusionRecipeJSON(plan.ActionBefore), plan.BeforePolicy); err != nil {
		return plan, err
	}
	if _, err := intrusionFail2banProcess("MainPID=" + plan.ProcessBefore + "\nActiveState=active\n"); err != nil {
		return plan, err
	}
	if !intrusionProcessTicksValid(plan.ProcessStartBefore) {
		return plan, errors.New("原入侵防护事务缺少内核进程起始身份；未仅凭旧进程号恢复")
	}
	if _, err := intrusionRuntimeJournalMatch("Current match filter:\n" + plan.JournalMatchBefore + "\n"); err != nil {
		return plan, err
	}
	if digest, err := hex.DecodeString(plan.EffectiveBefore); err != nil || len(digest) != 32 || strings.ToLower(plan.EffectiveBefore) != plan.EffectiveBefore {
		return plan, errors.New("入侵防护原有效配置的完整比较摘要缺失或不规范")
	}
	if err := intrusionJournalPorts(plan.TargetPorts); err != nil {
		return plan, err
	}
	settings, err := intrusionJournalSettings(plan.TargetSettings)
	if err != nil {
		return plan, err
	}
	for i, name := range []string{"jail", "manifest", "policy"} {
		if plan.Files[i].Name != name {
			return plan, errors.New("入侵防护事务文件范围不是固定三项")
		}
		if err := hardeningJournalStoredFile(plan.Files[i].Before, i > 0); err != nil {
			return plan, err
		}
	}
	var old softwareManifest
	installedAt := plan.StartedAt
	oldSettings, err := intrusionJournalBeforeSettings(plan)
	if err != nil {
		return plan, err
	}
	if plan.Action != "install" {
		old, err = intrusionJournalManifest(plan.Files[1].Before)
		if err != nil {
			return plan, err
		}
		installedAt = old.InstalledAt
	}
	if plan.Action == "update" && !reflect.DeepEqual(oldSettings, plan.TargetSettings) {
		return plan, errors.New("入侵防护更新不能偷偷改动原限额")
	}
	if plan.Action == "configure" && old.Version != intrusionTransactionVersion {
		return plan, errors.New("原版本须先完成受审更新，配置操作不能隐式升级")
	}
	jail := plan.Files[0].Before
	if !jail.Exists && plan.Action != "install" {
		return plan, errors.New("原受管 Jail 缺失，不能当作新装覆盖")
	}
	if err := intrusionConfigurationTreeValidate(plan.ConfigurationBefore, jail); err != nil {
		return plan, err
	}
	policyFile := plan.Files[2].Before
	if plan.Action == "install" {
		// BeforeSettings above requires all three known-absent fixed files.
		// The actual base Jail, its current bans and filters remain in place.
	} else if old.Version == intrusionTransactionVersion {
		var policy intrusionManagedPolicy
		if !policyFile.Exists || decodeProgramQueueJSON(policyFile.Data, &policy) != nil || intrusionPolicyValidate(policy) != nil || !reflect.DeepEqual(policy, plan.BeforePolicy) {
			return plan, errors.New("原受管策略文件与实际动作范围不一致")
		}
		canonical, e := intrusionJournalEncode(policy)
		if e != nil || !bytes.Equal(policyFile.Data, canonical) {
			return plan, errors.New("原受管策略不是完整规范记录")
		}
		expected, e := renderIntrusionManagedScope(old.Settings, policy)
		if e != nil || string(jail.Data) != expected {
			return plan, errors.New("原受管 Jail 已有外部改动，未覆盖")
		}
	} else {
		// Legacy 1.0 never recorded a custom action or SSH port. Only its exact
		// known bytes and numeric default scope may migrate, not guessed ports.
		if policyFile.Exists || string(jail.Data) != renderIntrusion(old.Settings) || !slices.Equal(plan.BeforePolicy.Ports, []int{22}) {
			return plan, errors.New("旧版受管 Jail 或默认范围无法核对，未自动接管")
		}
	}
	if len(plan.BansBefore) > 512 {
		return plan, errors.New("原封禁观察超过固定容量")
	}
	bans, err := intrusionBannedAddresses(strings.Join(plan.BansBefore, " "))
	if err != nil || len(bans) != len(plan.BansBefore) {
		return plan, errors.New("原封禁观察不是完整规范地址")
	}
	for i, ip := range bans {
		if ip.String() != plan.BansBefore[i] {
			return plan, errors.New("原封禁观察地址未规范排序")
		}
	}
	if err := intrusionJournalKernelBefore(plan, bans); err != nil {
		return plan, err
	}
	if err := intrusionJournalRemovalValidate(plan); err != nil {
		return plan, err
	}
	if plan.Action == "uninstall" {
		for i := range plan.Files {
			plan.Files[i].After = hardeningJournalFile{}
		}
		return plan, nil
	}
	targetPolicy := plan.BeforePolicy
	targetPolicy.Ports = slices.Clone(plan.TargetPorts)
	newJail, err := renderIntrusionManagedScope(settings, targetPolicy)
	if err != nil {
		return plan, err
	}
	manifest := softwareManifest{ID: "intrusion-prevention", Version: intrusionTransactionVersion, Settings: settings, InstalledAt: installedAt}
	manifestRaw, err := intrusionJournalEncode(manifest)
	if err != nil {
		return plan, err
	}
	policy := plan.BeforePolicy
	policy.Ports = slices.Clone(plan.TargetPorts)
	policyRaw, err := intrusionJournalEncode(policy)
	if err != nil {
		return plan, err
	}
	for i, data := range [][]byte{[]byte(newJail), manifestRaw, policyRaw} {
		owner := &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		if plan.Files[i].Before.Exists {
			value := *plan.Files[i].Before.Owner
			owner = &value
		}
		mode := uint32(0600)
		if i == 0 {
			mode = 0644
		}
		plan.Files[i].After = hardeningJournalFile{Exists: true, Mode: mode, Owner: owner, Data: data}
	}
	return plan, nil
}

// Deferred scopes carry complete positive absence evidence. No nft creation,
// empty set restoration, synthetic ban or executable statement is inferred
// from a missing table/owned scope. Historical observations are audit only.
func intrusionJournalKernelBefore(plan intrusionJournalPlan, bans []netip.Addr) error {
	scope := intrusionPolicyScope(plan.BeforePolicy, bans)
	switch plan.KernelState {
	case "rules_observed":
		if len(plan.KernelDirectory) != 0 {
			return errors.New("已观察规则不能混入另一份缺失目录")
		}
		_, err := planIntrusionNftPortChange(plan.KernelBefore, scope, plan.TargetPorts)
		return err
	case "table_absent":
		if len(bans) != 0 || len(plan.KernelBefore) != 0 {
			return errors.New("表尚未创建的原观察不能携带封禁或既存表快照")
		}
		return intrusionNftTableKnownAbsent(plan.KernelDirectory, plan.BeforePolicy.Table)
	case "scope_absent":
		if len(bans) != 0 || len(plan.KernelDirectory) != 0 {
			return errors.New("受管范围尚未创建的原观察不能携带封禁或缺失目录")
		}
		_, err := inspectIntrusionNftScope(plan.KernelBefore, scope)
		if !errors.Is(err, errIntrusionNftScopeAbsent) {
			return errors.New("共享表未提供完整可核对的受管范围缺失证据")
		}
		return nil
	default:
		return errors.New("入侵防护事务缺少明确的实际内核观察状态")
	}
}

func intrusionJournalValidate(plan intrusionJournalPlan) error {
	expected, err := intrusionJournalDerive(plan)
	if err != nil {
		return err
	}
	a, err := intrusionJournalEncode(plan)
	if err != nil {
		return err
	}
	b, err := intrusionJournalEncode(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return errors.New("入侵防护事务目标不是从完整原状态重新推导的固定结果")
	}
	return nil
}

func intrusionJournalDecode(raw []byte) (intrusionJournalPlan, error) {
	var plan intrusionJournalPlan
	if len(raw) < 1 || len(raw) > intrusionJournalBytes || decodeProgramQueueJSON(raw, &plan) != nil {
		return plan, errors.New("入侵防护事务私有记录损坏、未知或超限")
	}
	if err := intrusionJournalValidate(plan); err != nil {
		return plan, err
	}
	canonical, err := intrusionJournalEncode(plan)
	if err != nil || !bytes.Equal(canonical, raw) {
		return plan, errors.New("入侵防护事务不是原完整规范记录")
	}
	return plan, nil
}
