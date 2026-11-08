//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/appcatalog"
)

func (s *Service) remoteCopyVersionPreflight(version string, updating bool) error {
	all, err := s.allRemoteCopyInventory()
	if err != nil {
		return err
	}
	if updating {
		for _, r := range all.Records {
			if r.Result == nil && r.Retained == nil {
				return errors.New("独立备份待核对，保留原数据并拒绝更新应用")
			}
		}
	}
	if all.count() != 0 && !appcatalog.FilesSyncIndependentBackupSupported(version) {
		return errors.New("保留的独立备份不能用旧版应用重新标记；原数据保留")
	}
	if len(all.Unpublished) != 0 {
		if version != appcatalog.FilesSyncUnpublishedRetentionVersion {
			return errors.New("未发布主意图的原目录须用2.0.1保留核对；不安装旧版遮蔽原片段")
		}
		if updating {
			r, err := s.moduleInstalledRecord("files-sync")
			current, _ := r["version"].(string)
			if err != nil || !appcatalog.FilesSyncIndependentBackupSupported(current) {
				return errors.New("原安装身份不能核对，未借更新接管未发布片段")
			}
		}
		// Only this exact forward-compatible signed handler may be installed
		// while bounded unpublished intents await review. No record or fragment
		// is rewritten, interpreted as authority, cleared or marked successful.
	}
	return nil
}
