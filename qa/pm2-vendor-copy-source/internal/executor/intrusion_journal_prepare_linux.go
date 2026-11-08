//go:build linux

package executor

import (
	"context"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"

	"local/panel/internal/core"
)

type intrusionJobContextKey struct{}

func intrusionOriginalJob(ctx context.Context) (string, error) {
	id, _ := ctx.Value(intrusionJobContextKey{}).(string)
	if !core.ValidID(id) {
		return "", errors.New("入侵防护缺少原队列任务身份；未直接执行或创建替代任务")
	}
	return id, nil
}

// Existing-install configuration/update or fresh compatible-base adoption.
// This method observes the whole
// BEFORE state, then durably prepares the original plan before granting any
// write authority. It never synthesizes a replacement job, installs a package,
// changes service lifecycle, or silently adopts externally modified limits.
func (s *Service) intrusionPrepareOperation(ctx context.Context, lock *os.File, action string, requested map[string]any) (intrusionJournalPlan, []byte, error) {
	var plan intrusionJournalPlan
	id, err := intrusionOriginalJob(ctx)
	if err != nil {
		return plan, nil, err
	}
	if action != "configure" && action != "update" && action != "install" && action != "uninstall" || (action == "update" || action == "uninstall") && len(requested) != 0 {
		return plan, nil, errors.New("入侵防护原准备操作范围无效；更新不得附带限额变更")
	}
	if err = s.intrusionJournalRequireLock(lock); err != nil {
		return plan, nil, err
	}
	if err = s.intrusionJournalRequireClosed(); err != nil {
		return plan, nil, err
	}
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		return plan, nil, err
	}
	var settings map[string]int
	if action == "install" {
		for _, file := range files {
			if file.existed {
				return plan, nil, errors.New("新装入侵防护存在受管文件；未覆盖或隐式更新")
			}
		}
	} else {
		manifest, err := intrusionJournalManifest(hardeningJournalFromBackup(files[1]))
		if err != nil {
			return plan, nil, err
		}
		settings, err = intrusionSettings(manifest.Settings)
		if err != nil {
			return plan, nil, err
		}
	}
	target := settings
	if action == "configure" || action == "install" {
		target, err = intrusionSettings(requested)
		if err != nil {
			return plan, nil, err
		}
	}
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		return plan, nil, err
	}
	live, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil {
		return plan, nil, err
	}
	if action == "install" {
		settings = maps.Clone(live.Settings)
	} else if !reflect.DeepEqual(settings, live.Settings) {
		return plan, nil, errors.New("入侵防护原清单与实际运行限额不同；未覆盖外部配置")
	}
	dump, err := s.readIntrusionEffectiveConfiguration(ctx, live, settings)
	if err != nil {
		return plan, nil, err
	}
	targetPorts := slices.Clone(live.SSHPorts)
	var removal *intrusionRemovalEvidence
	if action == "uninstall" {
		candidate, err := s.readIntrusionRemovalCandidate(ctx, lock, tree, hardeningJournalFromBackup(files[0]), live, dump.Identity)
		if err != nil {
			return plan, nil, err
		}
		target = maps.Clone(candidate.Settings)
		targetPorts = slices.Clone(candidate.Ports)
		removal = &intrusionRemovalEvidence{Dump: slices.Clone(candidate.dump), SSHPorts: slices.Clone(live.SSHPorts)}
	}
	boot, err := os.ReadFile(s.systemPath("/proc/sys/kernel/random/boot_id"))
	if err != nil || len(boot) > 64 || string(boot) != strings.TrimSpace(string(boot))+"\n" || !hardeningBootID.MatchString(strings.TrimSpace(string(boot))) {
		return plan, nil, errors.New("入侵防护实际启动身份不能完整核对")
	}
	plan = intrusionJournalPlan{Format: 1, ID: id, Action: action, StartedAt: core.Now(), BootID: strings.TrimSpace(string(boot)), TargetVersion: intrusionTransactionVersion, TargetSettings: target, TargetPorts: targetPorts, Removal: removal, BeforePolicy: live.Policy, KernelState: live.KernelState, KernelBefore: live.Kernel, KernelDirectory: live.KernelDirectory, BansBefore: []string{}, ConfigurationBefore: tree, ActionBefore: live.Recipe, ProcessBefore: live.Process, ProcessStartBefore: live.ProcessStart, JournalMatchBefore: live.JournalMatch, EffectiveBefore: dump.Identity, Files: []hardeningJournalChange{}}
	if action == "install" {
		plan.InstallBeforeSettings = maps.Clone(settings)
	}
	for _, ip := range live.Bans {
		plan.BansBefore = append(plan.BansBefore, ip.String())
	}
	for i, name := range []string{"jail", "manifest", "policy"} {
		plan.Files = append(plan.Files, hardeningJournalChange{Name: name, Before: hardeningJournalFromBackup(files[i])})
	}
	plan, err = intrusionJournalDerive(plan)
	if err != nil {
		return plan, nil, err
	}
	if _, _, err = s.intrusionJournalObserveFilesAndTree(ctx, plan, "rolled_back"); err != nil {
		return plan, nil, err
	}
	again, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil {
		return plan, nil, err
	}
	if !slices.Equal(again.SSHPorts, intrusionJournalObservedSSHPorts(plan)) {
		return plan, nil, errors.New("入侵防护准备期间 SSH 实际端口改变，未猜测或跟随外部变更")
	}
	if err = intrusionJournalRuntimeAt(plan, again, "rolled_back"); err != nil {
		return plan, nil, err
	}
	if _, err = intrusionJournalKernelAccept(plan, again.Kernel, again.KernelDirectory, again.Bans); err != nil {
		return plan, nil, err
	}
	if err = s.intrusionJournalCheckEffective(ctx, plan, files, again); err != nil {
		return plan, nil, err
	}
	raw, err := s.intrusionJournalPrepare(lock, plan)
	if err != nil {
		return plan, nil, err
	}
	// A failure now leaves the fsynced original latch, never an implicit retry.
	if _, _, err = s.intrusionJournalObserveFilesAndTree(ctx, plan, "rolled_back"); err != nil {
		return plan, raw, err
	}
	_, err = s.readIntrusionTransactionRuntime(ctx, lock, plan, raw)
	return plan, raw, err
}
