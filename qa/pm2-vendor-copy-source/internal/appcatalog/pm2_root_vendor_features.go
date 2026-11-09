package appcatalog

import "errors"

const PM2RootVendorVersion = "7.0.4-compat11"
const PM2RootVendorFeature = "pm2-root-vendor-v1"

func validatePM2RootVendorRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == PM2RootVendorFeature
	}
	if !mentions && !(m.Version == PM2RootVendorVersion && (m.ID == "pm2-manager" || m.Delivery.Target == "pm2-manager")) {
		return false, nil
	}
	if m.ID != "pm2-manager" || m.Version != PM2RootVendorVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "pm2-manager" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != PM2RootVendorFeature {
		return true, errors.New("PM2 独立 Root 运行库须声明固定完整 compat11 及对应编译处理器")
	}
	if available == nil || !available(PM2RootVendorFeature) || !available(PM2EvidencePreservingStopFeature) {
		return true, errors.New("请先升级面板：缺少 PM2 独立 Root 副本、私有 inode 验收记录与保留证据停机处理器")
	}
	return true, nil
}
