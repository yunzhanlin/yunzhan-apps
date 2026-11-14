package appcatalog

import (
	"errors"
	"strings"
)

const AnalyticsQueryContextFeature = "website-analytics-query-context-v1"
const AnalyticsPeriodComparisonFeature = "website-analytics-period-comparison-v1"
const AnalyticsLayoutHeatmapFeature = "website-analytics-layout-heatmap-v1"
const AnalyticsGeographyFeature = "website-analytics-geography-v1"
const AnalyticsGeographyVersion = "2.4.5"
const AnalyticsSessionActivityFeature = "website-analytics-session-activity-v1"
const AnalyticsSessionActivityVersion = "2.4.6"

func AnalyticsVersionSupportsGeography(version string) bool {
	return version == AnalyticsGeographyVersion || version == AnalyticsSessionActivityVersion
}

// A label cannot give an older bundled workspace query-bound reports and
// exports. Keep all four previously signed 2.4.1 requirements intact.
func validateAnalyticsQueryRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == AnalyticsQueryContextFeature || feature == AnalyticsPeriodComparisonFeature || feature == AnalyticsLayoutHeatmapFeature || feature == AnalyticsGeographyFeature || feature == AnalyticsSessionActivityFeature
	}
	if m.ID != "website-analytics" {
		if mentions {
			return true, errors.New("查询上下文、周期对比、页面热图和地理分布处理器仅属于网站分析")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "2.4.2")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	wanted := map[string]bool{AnalyticsSessionFeature: false, AnalyticsClientAddressFeature: false, AnalyticsRoutePerformanceFeature: false, AnalyticsNavigationOrderFeature: false, AnalyticsQueryContextFeature: false}
	switch m.Version {
	case "2.4.2":
	case "2.4.3":
		wanted[AnalyticsPeriodComparisonFeature] = false
	case "2.4.4", AnalyticsGeographyVersion, AnalyticsSessionActivityVersion:
		wanted[AnalyticsPeriodComparisonFeature] = false
		wanted[AnalyticsLayoutHeatmapFeature] = false
		if AnalyticsVersionSupportsGeography(m.Version) {
			wanted[AnalyticsGeographyFeature] = false
		}
		if m.Version == AnalyticsSessionActivityVersion {
			wanted[AnalyticsSessionActivityFeature] = false
		}
	default:
		return true, errors.New("网站分析须声明固定完整版本")
	}
	if m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != len(wanted) {
		return true, errors.New("网站分析须声明对应版本的全部必需处理器")
	}
	for _, feature := range m.RequiredPanelFeatures {
		seen, ok := wanted[feature]
		if !ok || seen {
			return true, errors.New("网站分析的处理器声明无效或重复")
		}
		wanted[feature] = true
	}
	for feature, seen := range wanted {
		if !seen || available == nil || !available(feature) {
			return true, errors.New("请先升级面板：缺少当前版本所需的网站分析处理器")
		}
	}
	return true, nil
}
