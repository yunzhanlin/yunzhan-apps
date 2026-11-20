package appcatalog

import "errors"

const PM2ConfigurationArchiveVersion = "7.0.4-compat12"
const PM2ConfigurationArchiveFeature = "pm2-configuration-archive-v1"

func validatePM2ConfigurationArchiveRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, f := range m.RequiredPanelFeatures {
		mentions = mentions || f == PM2ConfigurationArchiveFeature
	}
	if !mentions && !(m.Version == PM2ConfigurationArchiveVersion && (m.ID == "pm2-manager" || m.Delivery.Target == "pm2-manager")) {
		return false, nil
	}
	if m.ID != "pm2-manager" || m.Version != PM2ConfigurationArchiveVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "pm2-manager" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != PM2ConfigurationArchiveFeature {
		return true, errors.New("配置封存仅允许固定完整 compat12 及专用编译处理器")
	}
	if available == nil || !available(PM2ConfigurationArchiveFeature) || !available(PM2RootVendorFeature) || !available(PM2EvidencePreservingStopFeature) {
		return true, errors.New("请先升级面板：缺少配置封存恢复、独立 Root 运行库或证据保全停机处理器")
	}
	return true, nil
}
