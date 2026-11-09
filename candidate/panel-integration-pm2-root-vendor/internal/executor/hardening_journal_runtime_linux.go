//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"local/panel/internal/core"
)

type hardeningJobContextKey struct{}

func (s *Service) hardeningOriginalJob(ctx context.Context) (string, error) {
	id, _ := ctx.Value(hardeningJobContextKey{}).(string)
	if id == "" && s.Config.SystemRoot != "/" {
		return core.ID(), nil
	} // Declared isolated fixtures only.
	if !core.ValidID(id) {
		return "", errors.New("系统加固缺少原队列任务身份，未直接执行或创建替代任务")
	}
	return id, nil
}

func (s *Service) hardeningOriginalReceipt(id, action, profile string, add func(string)) (bool, error) {
	inventory, err := s.hardeningJournalInventoryRead()
	if err != nil {
		return false, err
	}
	if prior, exists := inventory.Records[id]; exists {
		if !hardeningJournalRequestMatches(prior.Plan, action, profile) {
			return true, errors.New("原加固任务身份已绑定不同请求，未重复执行")
		}
		if prior.State == "rolled_back" {
			return true, errors.New("原加固任务已闭合恢复，不将失败任务重放为新变更")
		}
		add("原加固任务已有完整已提交回执；未重放参数或改写原任务，当前健康状态仍需独立读取")
		return true, nil
	}
	return false, nil
}

func (s *Service) hardeningPrepareOperation(ctx context.Context, id, action, profile string, before map[string]string, config []fileBackup, manifest fileBackup) (hardeningJournalPlan, []byte, error) {
	var plan hardeningJournalPlan
	if len(config) != 2 || !core.ValidID(id) {
		return plan, nil, errors.New("加固原准备范围或任务身份无效")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 64 {
		return plan, nil, errors.New("加固实际启动身份不可核对")
	}
	plan = hardeningJournalPlan{Format: 1, ID: id, Action: action, StartedAt: core.Now(), BootID: strings.TrimSpace(string(boot)), ToProfile: profile, BeforeKernel: maps.Clone(before), Files: []hardeningJournalChange{{Name: "current", Before: hardeningJournalFromBackup(config[0])}, {Name: "legacy", Before: hardeningJournalFromBackup(config[1])}, {Name: "manifest", Before: hardeningJournalFromBackup(manifest)}}}
	plan.TargetVersion = core.HardeningAppVersion
	if manifest.existed && action != "update" {
		old, readErr := hardeningJournalManifest(plan.Files[2].Before)
		if readErr != nil {
			return plan, nil, readErr
		}
		plan.TargetVersion = old.Version
	}
	plan, err = hardeningJournalDerive(plan)
	if err != nil {
		return plan, nil, err
	}
	if err = s.hardeningJournalVerifyState(ctx, plan, "rolled_back"); err != nil {
		return plan, nil, err
	}
	raw, err := s.hardeningJournalPrepare(plan)
	return plan, raw, err
}

func (s *Service) hardeningCompensateOperation(plan hardeningJournalPlan, raw []byte, cause error) error {
	inventory, readErr := s.hardeningJournalInventoryRead()
	if readErr != nil {
		return errors.Join(cause, hardeningJournalError("终态核对", readErr))
	}
	if terminal, exists := inventory.Records[plan.ID]; exists && terminal.State == "committed" {
		if terminal.PlanSHA256 != hardeningJournalDigest(raw) {
			return errors.Join(cause, errors.New("加固原提交回执冲突，未执行补偿覆盖"))
		}
		return errors.Join(cause, errors.New("原加固事务已持久提交；仅收尾尚需核对，未回滚已提交的参数或伪造原任务成功"))
	}
	paths := s.hardeningJournalPaths()
	config := []fileBackup{plan.Files[0].Before.backup(paths[0]), plan.Files[1].Before.backup(paths[1])}
	beforeManifest := plan.Files[2].Before.backup(paths[2])
	manifestErr := s.hardeningRestoreManifest(beforeManifest, plan.Files[2].After.Data, plan.Action == "uninstall")
	rollbackErr := s.hardeningRollback(plan.BeforeKernel, config, cause)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if verifyErr := s.hardeningJournalVerifyState(ctx, plan, "rolled_back"); verifyErr != nil {
		return errors.Join(rollbackErr, manifestErr, hardeningJournalError("恢复核对", verifyErr))
	}
	if err := s.hardeningJournalPublishTerminal(plan, raw, "rolled_back", ""); err != nil {
		return errors.Join(rollbackErr, manifestErr, hardeningJournalError("恢复回执持久化", err))
	}
	return errors.Join(rollbackErr, manifestErr)
}

func hardeningSyncFileParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Service) applyHardeningTransition(ctx context.Context, settings map[string]any, install bool, add func(string)) error {
	action := "configure"
	if install {
		action = "install"
	}
	return s.applyHardeningOperation(ctx, settings, action, add)
}

func (s *Service) applyHardeningOperation(ctx context.Context, settings map[string]any, action string, add func(string)) error {
	if action != "install" && action != "configure" && action != "update" {
		return errors.New("系统加固操作无效")
	}
	install := action == "install"
	profile, err := hardeningProfile(settings)
	if err != nil {
		return err
	}
	id, err := s.hardeningOriginalJob(ctx)
	if err != nil {
		return err
	}
	lock, err := s.hardeningMutationLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if done, err := s.hardeningOriginalReceipt(id, action, profile, add); done || err != nil {
		return err
	}
	if err = s.hardeningJournalRequireClosed(); err != nil {
		return err
	}
	old, oldErr := s.readSoftwareManifest("system-hardening")
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return fmt.Errorf("系统加固安装记录无法核对；未执行变更: %w", oldErr)
	}
	if install && oldErr == nil {
		return errors.New("系统基线加固已安装，请使用配置操作")
	}
	if !install && oldErr != nil {
		return errors.New("请先安装系统基线加固")
	}
	if action == "update" {
		oldProfile, profileErr := hardeningProfile(old.Settings)
		if profileErr != nil || profile != oldProfile {
			return errors.New("更新不得替换原加固策略")
		}
		if err = s.hardeningVerify(ctx, hardeningValues(oldProfile)); err != nil {
			return errors.New("原加固实际参数存在偏差，未以更新覆盖或猜测迁移")
		}
	}
	keys := hardeningValues(profile)
	if oldErr == nil {
		previous, err := hardeningPrevious(old)
		if err != nil {
			return err
		}
		maps.Copy(keys, previous)
	}
	before, err := s.hardeningReadValues(ctx, keys)
	if err != nil {
		return err
	}
	config, err := s.hardeningConfigBackups()
	if err != nil {
		return err
	}
	manifest, err := s.hardeningManifestBackup()
	if err != nil {
		return err
	}
	if err = hardeningConfigMatches(config, old, oldErr == nil); err != nil {
		return err
	}
	if err = hardeningManifestMatches(manifest, old, oldErr == nil); err != nil {
		return err
	}
	plan, raw, err := s.hardeningPrepareOperation(ctx, id, action, profile, before, config, manifest)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return s.hardeningCompensateOperation(plan, raw, cause) }
	if err = s.hardeningOriginalFilesCurrent(config, manifest); err != nil {
		return fail(err)
	}
	path := config[0].path
	candidate := plan.Files[0].After
	if err = atomicWriteWithOwner(path, candidate.Data, os.FileMode(candidate.Mode), candidate.Owner); err != nil {
		return fail(err)
	}
	if config[1].existed {
		if err = os.Remove(config[1].path); err != nil {
			return fail(err)
		}
		if err = hardeningSyncFileParent(config[1].path); err != nil {
			return fail(err)
		}
	}
	if _, err = s.Config.Run(ctx, "/usr/sbin/sysctl", "-p", path); err != nil {
		return fail(err)
	}
	active := hardeningValues(profile)
	for _, key := range hardeningSorted(plan.AfterKernel) {
		if _, keep := active[key]; !keep {
			if _, err = s.Config.Run(ctx, "/usr/sbin/sysctl", "-w", key+"="+plan.AfterKernel[key]); err != nil {
				return fail(err)
			}
		}
	}
	if err = s.hardeningVerify(ctx, plan.AfterKernel); err != nil {
		return fail(err)
	}
	now, err := s.hardeningManifestBackup()
	if err != nil || !hardeningBackupSame(now, manifest) {
		return fail(errors.New("加固原清单在应用期间改变，未覆盖外来对象"))
	}
	candidate = plan.Files[2].After
	if err = atomicWriteWithOwner(manifest.path, candidate.Data, os.FileMode(candidate.Mode), candidate.Owner); err != nil {
		return fail(err)
	}
	if err = s.hardeningJournalPublishTerminal(plan, raw, "committed", ""); err != nil {
		return fail(err)
	}
	add("原任务完整恢复计划已先持久保存；实际参数、完整三文件和提交回执均已核对")
	add("新增受管参数记录本次原值；严格模式使用可恢复 BPF=2；退出当前基线的参数已恢复并释放归属")
	return nil
}

func (s *Service) uninstallHardeningTransition(ctx context.Context, add func(string)) error {
	id, err := s.hardeningOriginalJob(ctx)
	if err != nil {
		return err
	}
	lock, err := s.hardeningMutationLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if done, err := s.hardeningOriginalReceipt(id, "uninstall", "", add); done || err != nil {
		return err
	}
	if err = s.hardeningJournalRequireClosed(); err != nil {
		return err
	}
	old, err := s.readSoftwareManifest("system-hardening")
	if err != nil {
		return errors.New("系统加固原安装清单不可核对，未移除或猜测原值")
	}
	keys, err := hardeningPrevious(old)
	if err != nil {
		return err
	}
	before, err := s.hardeningReadValues(ctx, keys)
	if err != nil {
		return err
	}
	config, err := s.hardeningConfigBackups()
	if err != nil {
		return err
	}
	manifest, err := s.hardeningManifestBackup()
	if err != nil {
		return err
	}
	plan, raw, err := s.hardeningPrepareOperation(ctx, id, "uninstall", "", before, config, manifest)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return s.hardeningCompensateOperation(plan, raw, cause) }
	if err = s.hardeningOriginalFilesCurrent(config, manifest); err != nil {
		return fail(err)
	}
	for _, key := range hardeningSorted(plan.AfterKernel) {
		if before[key] != plan.AfterKernel[key] {
			if _, err = s.Config.Run(ctx, "/usr/sbin/sysctl", "-w", key+"="+plan.AfterKernel[key]); err != nil {
				return fail(err)
			}
		}
	}
	if err = s.hardeningVerify(ctx, plan.AfterKernel); err != nil {
		return fail(err)
	}
	for _, file := range append(config, manifest) {
		if file.existed {
			if err = os.Remove(file.path); err != nil {
				return fail(err)
			}
			if err = hardeningSyncFileParent(file.path); err != nil {
				return fail(err)
			}
		}
	}
	if err = s.hardeningJournalPublishTerminal(plan, raw, "committed", ""); err != nil {
		return fail(err)
	}
	add("原任务恢复计划和终态已持久保存；仅恢复当前受管参数并移除自有文件，未改动已释放参数或其他配置")
	return nil
}

// A committed receipt is historical fact, not a statement of present health.
func hardeningJournalSameRawPlan(plan hardeningJournalPlan, raw []byte) bool {
	encoded, err := hardeningJournalEncode(plan)
	return err == nil && bytes.Equal(encoded, raw)
}
