package appcatalog

import (
	"errors"
	"strings"
)

const PM2EvidencePreservingStopVersion = "7.0.4-compat10"
const PM2EvidencePreservingStopFeature = "pm2-evidence-preserving-stop-v1"

// A new manifest must not relabel the older stop path which first requires a
// writable, complete retrospective/configuration store. Both online pulls
// and offline executor verification require this compiled implementation.
func validatePM2StopRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == PM2EvidencePreservingStopFeature
	}
	if !mentions && m.ID != "pm2-manager" && m.Delivery.Target != "pm2-manager" {
		return false, nil
	}
	legacy := false
	base, _, _ := strings.Cut(m.Version, "-")
	if comparison, valid := CompareVersions(base, "7.0.4"); valid && comparison < 0 {
		legacy = true
	}
	for _, version := range []string{"7.0.4", "7.0.4-compat1", "7.0.4-compat2", "7.0.4-compat3", "7.0.4-compat4", "7.0.4-compat5", "7.0.4-compat6", "7.0.4-compat7", "7.0.4-compat8", "7.0.4-compat9"} {
		legacy = legacy || m.Version == version
	}
	if !mentions && legacy && m.ID == "pm2-manager" {
		return false, nil
	}
	if m.ID != "pm2-manager" || m.Version != PM2EvidencePreservingStopVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "pm2-manager" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != PM2EvidencePreservingStopFeature {
		return true, errors.New("PM2 保留原证据停机须声明固定完整 compat10 及独立编译处理器")
	}
	if available == nil || !available(PM2EvidencePreservingStopFeature) {
		return true, errors.New("请先升级面板：缺少 PM2 原项目锁、独立停机核对及存储故障结果处理器")
	}
	return true, nil
}
