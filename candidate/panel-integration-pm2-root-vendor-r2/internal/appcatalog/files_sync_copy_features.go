package appcatalog

import (
	"errors"
	"strings"
)

// A label on the existing SFTP archive must not claim independent local bytes.
const FilesSyncIndependentBackupVersion = "2.0.0"
const FilesSyncIndependentBackupFeature = "files-sync-root-independent-backup-v1"

func validateFilesSyncCopyRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == FilesSyncIndependentBackupFeature
	}
	if m.ID != "files-sync" {
		if mentions {
			return true, errors.New("文件同步独立备份处理器不能授权其他应用")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, FilesSyncIndependentBackupVersion)
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != FilesSyncIndependentBackupVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != FilesSyncIndependentBackupFeature {
		return true, errors.New("独立备份须声明精确文件同步2.0.0及本机Root私有副本处理器")
	}
	if available == nil || !available(FilesSyncIndependentBackupFeature) {
		return true, errors.New("请先升级面板：缺少Root独立备份、内容核验和显式恢复处理器")
	}
	return true, nil
}
