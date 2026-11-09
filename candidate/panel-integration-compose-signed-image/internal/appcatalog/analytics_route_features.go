package appcatalog

import (
	"errors"
	"strings"
)

const AnalyticsRoutePerformanceFeature = "analytics-route-readiness-v1"

// An application label cannot activate the numeric route collector on older
// Core/Root binaries. The existing session and protected-ingress contracts are
// mandatory too; this is not an alternative unbounded collector.
func validateAnalyticsRouteRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == AnalyticsRoutePerformanceFeature
	}
	if m.ID != "website-analytics" {
		if mentions {
			return true, errors.New("独立路由性能处理器仅属于网站分析 2.4.0")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "2.4.0")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "2.4.0" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 3 {
		return true, errors.New("网站分析 2.4.0 须声明固定完整版本和三个必需处理器")
	}
	seen := map[string]bool{}
	for _, feature := range m.RequiredPanelFeatures {
		if feature != AnalyticsSessionFeature && feature != AnalyticsClientAddressFeature && feature != AnalyticsRoutePerformanceFeature || seen[feature] {
			return true, errors.New("网站分析 2.4.0 的处理器声明无效或重复")
		}
		seen[feature] = true
	}
	for _, feature := range []string{AnalyticsSessionFeature, AnalyticsClientAddressFeature, AnalyticsRoutePerformanceFeature} {
		if !seen[feature] {
			return true, errors.New("网站分析 2.4.0 缺少必需处理器")
		}
		if available == nil || !available(feature) {
			return true, errors.New("请先升级面板：当前程序未提供独立路由、完整会话和受保护采集处理器")
		}
	}
	return true, nil
}
