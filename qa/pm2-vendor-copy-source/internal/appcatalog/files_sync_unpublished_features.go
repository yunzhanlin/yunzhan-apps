package appcatalog

import (
	"errors"
	"strings"
)

const FilesSyncUnpublishedRetentionVersion = "2.0.1"
const FilesSyncUnpublishedRetentionFeature = "files-sync-unpublished-retention-v1"

func FilesSyncIndependentBackupSupported(version string) bool {
	return version == FilesSyncIndependentBackupVersion || version == FilesSyncUnpublishedRetentionVersion
}

// The old independent-copy ABI must not authorize forensic retention merely
// because the package label advanced. Preserve its exact 2.0.0 contract.
func validateFilesSyncUnpublishedRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, f := range m.RequiredPanelFeatures {
		mentions = mentions || f == FilesSyncUnpublishedRetentionFeature
	}
	if m.ID != "files-sync" {
		if mentions {
			return true, errors.New("未发布原片段保留处理器不能授权其他应用")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	cmp, valid := CompareVersions(base, FilesSyncUnpublishedRetentionVersion)
	if !mentions && (!valid || cmp < 0) {
		return false, nil
	}
	features := map[string]bool{}
	for _, f := range m.RequiredPanelFeatures {
		if features[f] {
			return true, errors.New("文件同步2.0.1须声明两个不同的固定处理器")
		}
		features[f] = true
	}
	if m.Version != FilesSyncUnpublishedRetentionVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "files-sync" || m.Delivery.ManageRoute != "app-modules" || len(features) != 2 || !features[FilesSyncIndependentBackupFeature] || !features[FilesSyncUnpublishedRetentionFeature] {
		return true, errors.New("未发布原片段保留须声明精确文件同步2.0.1、独立副本及原片段保留处理器")
	}
	if available == nil || !available(FilesSyncIndependentBackupFeature) || !available(FilesSyncUnpublishedRetentionFeature) {
		return true, errors.New("请先升级面板：缺少未发布主意图的有界离线核对、原字节保留和固定版本处理器")
	}
	return true, nil
}
