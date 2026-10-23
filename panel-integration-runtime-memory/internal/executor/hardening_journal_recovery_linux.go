//go:build linux

package executor

import (
	"context"
	"errors"
	"os"

	"local/panel/internal/core"
)

// Explicit compensation against ONE immutable original plan. It is never an
// implicit install/configure retry, and never repairs third-party file state.
func (s *Service) recoverHardeningOperation(ctx context.Context, settings map[string]any, add func(string)) error {
	normal, err := core.NormalizeHardeningRecovery(settings)
	if err != nil {
		return err
	}
	id := normal["transaction_id"].(string)
	digest := normal["sha256"].(string)
	recoveryJob, err := s.hardeningOriginalJob(ctx)
	if err != nil {
		return err
	}
	lock, err := s.hardeningMutationLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	plan, raw, readErr := s.hardeningJournalPending()
	inventory, err := s.hardeningJournalInventoryRead()
	if err != nil {
		return err
	}
	if errors.Is(readErr, os.ErrNotExist) {
		terminal, exists := inventory.Records[id]
		if !exists || terminal.PlanSHA256 != digest {
			return errors.New("原加固恢复记录不存在或摘要不符，未创建替代事务")
		}
		add("原加固事务已有完整终态回执且待恢复记录已闭合；仅核对原身份，未重复应用或补偿参数")
		return nil
	}
	if readErr != nil {
		return readErr
	}
	if plan.ID != id || hardeningJournalDigest(raw) != digest {
		return errors.New("加固原事务或完整摘要已改变，未执行恢复")
	}
	if terminal, exists := inventory.Records[id]; exists {
		if terminal.PlanSHA256 != digest || !hardeningJournalSameRawPlan(terminal.Plan, raw) {
			return errors.New("原加固终态和待恢复记录冲突，未覆盖")
		}
		if err = s.hardeningJournalVerifyState(ctx, plan, terminal.State); err != nil {
			return err
		}
		if err = s.hardeningJournalRemoveExact(plan, raw); err != nil {
			return err
		}
		add("原事务已有实际状态对应的完整终态；仅完成私有记录收尾，未回滚已提交的变更或重放原任务")
		return nil
	}
	if err = s.hardeningJournalRecoveryPreflight(ctx, plan); err != nil {
		return err
	}
	paths := s.hardeningJournalPaths()
	for i, change := range plan.Files {
		if err = ctx.Err(); err != nil {
			return err
		}
		current, err := s.hardeningJournalCurrentFiles()
		if err != nil {
			return err
		}
		before := change.Before.backup(paths[i])
		if hardeningBackupSame(current[i], before) {
			continue
		}
		if !hardeningBackupSame(current[i], change.After.backup(paths[i])) {
			return errors.New("加固文件在恢复期间改变，原待恢复记录保留")
		}
		if err = restoreFiles([]fileBackup{before}); err != nil {
			return hardeningJournalError("原文件恢复", err)
		}
		if err = hardeningSyncFileParent(paths[i]); err != nil {
			return hardeningJournalError("原文件目录持久化", err)
		}
	}
	for _, key := range hardeningSorted(plan.BeforeKernel) {
		actual, err := s.sysctlValue(ctx, key)
		if err != nil {
			return err
		}
		if actual == plan.BeforeKernel[key] {
			continue
		}
		if actual != plan.AfterKernel[key] {
			return errors.New("内核参数在恢复期间出现外部改动，保留原待恢复计划")
		}
		if err = hardeningReversible(key, actual, plan.BeforeKernel[key]); err != nil {
			return err
		}
		if _, err = s.Config.Run(ctx, "/usr/sbin/sysctl", "-w", key+"="+plan.BeforeKernel[key]); err != nil {
			return hardeningJournalError("实际内核恢复", err)
		}
	}
	if err = s.hardeningJournalVerifyState(ctx, plan, "rolled_back"); err != nil {
		return err
	}
	if err = s.hardeningJournalPublishTerminal(plan, raw, "rolled_back", recoveryJob); err != nil {
		return err
	}
	add("按原事务完整摘要恢复了已核对的原参数和文件；持久保留原失败任务身份与恢复回执，未重放安装或配置")
	return nil
}
