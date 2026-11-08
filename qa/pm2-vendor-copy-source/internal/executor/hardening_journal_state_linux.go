//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"maps"
)

func (s *Service) hardeningJournalCurrentFiles() ([]fileBackup, error) {
	config, err := s.hardeningConfigBackupsMode(false)
	if err != nil {
		return nil, err
	}
	manifest, err := s.hardeningManifestBackup()
	if err != nil {
		return nil, err
	}
	return append(config, manifest), nil
}

func (s *Service) hardeningJournalVerifyState(ctx context.Context, plan hardeningJournalPlan, state string) error {
	if err := hardeningJournalValidate(plan); err != nil {
		return err
	}
	if state != "committed" && state != "rolled_back" {
		return errors.New("不能以非闭合状态发布加固终态")
	}
	kernel := plan.AfterKernel
	if state == "rolled_back" {
		kernel = plan.BeforeKernel
	}
	if err := s.hardeningVerify(ctx, kernel); err != nil {
		return err
	}
	current, err := s.hardeningJournalCurrentFiles()
	if err != nil {
		return err
	}
	paths := s.hardeningJournalPaths()
	for i, change := range plan.Files {
		wanted := change.After
		if state == "rolled_back" {
			wanted = change.Before
		}
		if !hardeningBackupSame(current[i], wanted.backup(paths[i])) {
			return errors.New("加固原内核或完整文件状态未闭合，未发布成功或恢复回执")
		}
	}
	return nil
}

// A mixed before/after state is expected after interruption. Any third state
// belongs to an unknown writer and is preserved before compensation begins.
func (s *Service) hardeningJournalRecoveryPreflight(ctx context.Context, plan hardeningJournalPlan) error {
	if err := hardeningJournalValidate(plan); err != nil {
		return err
	}
	actual, err := s.hardeningReadValues(ctx, plan.BeforeKernel)
	if err != nil {
		return err
	}
	for key, value := range actual {
		if value != plan.BeforeKernel[key] && value != plan.AfterKernel[key] {
			return fmt.Errorf("内核参数 %s 不是原事务的前值或后值，未覆盖外部变更", key)
		}
		if err = hardeningReversible(key, value, plan.BeforeKernel[key]); err != nil {
			return err
		}
	}
	files, err := s.hardeningJournalCurrentFiles()
	if err != nil {
		return err
	}
	paths := s.hardeningJournalPaths()
	for i, change := range plan.Files {
		if !hardeningBackupSame(files[i], change.Before.backup(paths[i])) && !hardeningBackupSame(files[i], change.After.backup(paths[i])) {
			return errors.New("加固文件不是原事务的完整前后状态，未删除、修复或覆盖外部对象")
		}
	}
	return nil
}

func hardeningJournalRequestMatches(plan hardeningJournalPlan, action, profile string) bool {
	return plan.Action == action && plan.ToProfile == profile
}

func hardeningJournalKernelBeforeCopy(plan hardeningJournalPlan) map[string]string {
	return maps.Clone(plan.BeforeKernel)
}
