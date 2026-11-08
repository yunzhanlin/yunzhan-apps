package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

// Includes sealed native-engine activation, complete body parsing/storage
// contracts and unchanged-site no-op preservation. A version badge alone on a
// metadata-only or earlier compiled panel cannot authorize Apache native2.4.
const ApacheNativeBodySiteFeature = "apache-native-body-site-transactions-v1"
const ApacheNativeBodyAppVersion = "2.4.0"

func validateApacheNativeBodyRequirement(m Manifest, available func(string) bool) (bool, error) {
	has, needs := false, false
	for _, feature := range m.RequiredPanelFeatures {
		has = has || feature == ApacheNativeBodySiteFeature
	}
	if m.ID == "apache-waf" || m.Delivery.Target == "apache-waf" {
		base, _, _ := strings.Cut(m.Version, "-")
		comparison, valid := CompareVersions(base, ApacheNativeBodyAppVersion)
		if !valid {
			return true, errors.New("Apache 请求防护应用版本无法核对")
		}
		needs = comparison >= 0
	}
	if !has && !needs {
		return false, nil
	}
	if m.ID != "apache-waf" || m.Version != ApacheNativeBodyAppVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "apache-waf" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != ApacheNativeBodySiteFeature {
		return true, errors.New("Apache 原生请求体防护仅允许固定2.4.0、apache-waf目标和独立站点事务处理器声明")
	}
	if available == nil || !available(ApacheNativeBodySiteFeature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", ApacheNativeBodySiteFeature)
	}
	return true, nil
}
