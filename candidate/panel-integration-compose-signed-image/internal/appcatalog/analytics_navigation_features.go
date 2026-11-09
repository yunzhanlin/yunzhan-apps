package appcatalog

import (
	"errors"
	"strings"
)

const AnalyticsNavigationOrderFeature = "analytics-navigation-order-v1"

// A new label cannot make a previous compiled collector order asynchronous
// browser visits. Keep the previously signed 2.4.0 three-handler ABI intact.
func validateAnalyticsNavigationRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == AnalyticsNavigationOrderFeature
	}
	if m.ID != "website-analytics" {
		if mentions {
			return true, errors.New("浏览顺序处理器仅属于网站分析 2.4.1")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "2.4.1")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "2.4.1" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 4 {
		return true, errors.New("网站分析 2.4.1 须声明固定完整版本和四个必需处理器")
	}
	seen := map[string]bool{}
	for _, feature := range m.RequiredPanelFeatures {
		if feature != AnalyticsSessionFeature && feature != AnalyticsClientAddressFeature && feature != AnalyticsRoutePerformanceFeature && feature != AnalyticsNavigationOrderFeature || seen[feature] {
			return true, errors.New("网站分析 2.4.1 的处理器声明无效或重复")
		}
		seen[feature] = true
	}
	for _, feature := range []string{AnalyticsSessionFeature, AnalyticsClientAddressFeature, AnalyticsRoutePerformanceFeature, AnalyticsNavigationOrderFeature} {
		if !seen[feature] || available == nil || !available(feature) {
			return true, errors.New("请先升级面板：缺少浏览顺序、路由性能、完整会话或受保护采集处理器")
		}
	}
	return true, nil
}
