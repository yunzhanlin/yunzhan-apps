package appcatalog

import (
	"errors"
	"strings"
)

const AnalyticsQueryContextFeature = "website-analytics-query-context-v1"

// A label cannot give an older bundled workspace query-bound reports and
// exports. Keep all four previously signed 2.4.1 requirements intact.
func validateAnalyticsQueryRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == AnalyticsQueryContextFeature
	}
	if m.ID != "website-analytics" {
		if mentions {
			return true, errors.New("查询上下文处理器仅属于网站分析2.4.2")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "2.4.2")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "2.4.2" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 5 {
		return true, errors.New("网站分析2.4.2须声明固定完整版本和五个必需处理器")
	}
	wanted := map[string]bool{AnalyticsSessionFeature: false, AnalyticsClientAddressFeature: false, AnalyticsRoutePerformanceFeature: false, AnalyticsNavigationOrderFeature: false, AnalyticsQueryContextFeature: false}
	for _, feature := range m.RequiredPanelFeatures {
		seen, ok := wanted[feature]
		if !ok || seen {
			return true, errors.New("网站分析2.4.2的处理器声明无效或重复")
		}
		wanted[feature] = true
	}
	for feature, seen := range wanted {
		if !seen || available == nil || !available(feature) {
			return true, errors.New("请先升级面板：缺少网站分析查询上下文或原有采集处理器")
		}
	}
	return true, nil
}
