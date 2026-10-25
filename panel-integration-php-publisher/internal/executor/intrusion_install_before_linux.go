//go:build linux

package executor

import (
	"errors"
	"maps"
)

// A real base Jail is not an installed panel app. Fresh installation records
// its independently observed limits, never a fabricated manifest. Existing
// app operations cannot supply this separate install-only authority.
func intrusionJournalBeforeSettings(plan intrusionJournalPlan) (map[string]int, error) {
	if len(plan.Files) != 3 {
		return nil, errors.New("入侵防护原固定文件范围不完整")
	}
	if plan.Action == "install" {
		for i, file := range plan.Files {
			if file.Before.Exists || hardeningJournalStoredFile(file.Before, i > 0) != nil {
				return nil, errors.New("新装入侵防护需要三个受管文件均明确缺失；未覆盖或隐式更新")
			}
		}
		if _, err := intrusionJournalSettings(plan.InstallBeforeSettings); err != nil {
			return nil, errors.New("新装入侵防护缺少独立的实际运行限额")
		}
		return maps.Clone(plan.InstallBeforeSettings), nil
	}
	if plan.InstallBeforeSettings != nil {
		return nil, errors.New("既存入侵防护事务不能附带新装原限额或替代原清单")
	}
	manifest, err := intrusionJournalManifest(plan.Files[1].Before)
	if err != nil {
		return nil, err
	}
	return intrusionSettings(manifest.Settings)
}
