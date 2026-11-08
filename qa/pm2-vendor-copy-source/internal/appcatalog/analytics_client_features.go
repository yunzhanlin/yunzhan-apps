package appcatalog

import (
	"errors"
	"strings"
)

const AnalyticsClientAddressFeature = "analytics-managed-client-address-v1"

// The protected ingress, unknown-identity accounting and bounded collector
// must all be compiled in. A new application label cannot grant them.
func validateAnalyticsClientAddressRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == AnalyticsClientAddressFeature
	}
	if m.ID != "website-analytics" {
		if mentions {
			return true, errors.New("采集代理地址处理器仅属于 website-analytics 2.3.2")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "2.3.2")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "2.3.2" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 2 {
		return true, errors.New("网站分析 2.3.2 须声明固定完整版本、原会话与受保护采集地址处理器")
	}
	session, address := false, false
	for _, feature := range m.RequiredPanelFeatures {
		switch feature {
		case AnalyticsSessionFeature:
			if session {
				return true, errors.New("网站分析处理器声明重复")
			}
			session = true
		case AnalyticsClientAddressFeature:
			if address {
				return true, errors.New("网站分析处理器声明重复")
			}
			address = true
		default:
			return true, errors.New("网站分析 2.3.2 含未知处理器声明")
		}
	}
	if !session || !address {
		return true, errors.New("网站分析 2.3.2 缺少固定处理器声明")
	}
	if available == nil || !available(AnalyticsSessionFeature) || !available(AnalyticsClientAddressFeature) {
		return true, errors.New("请先升级面板：当前程序未提供受保护的采集地址与完整会话处理器")
	}
	return true, nil
}
