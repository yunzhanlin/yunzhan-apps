package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

const ApacheNativeCCSiteFeature = "apache-native-cc-site-transactions-v1"
const ApacheNativeCCAppVersion = "2.5.0"

func validateApacheNativeCCRequirement(m Manifest, available func(string) bool) (bool, error) {
	has, needs := false, false
	for _, feature := range m.RequiredPanelFeatures {
		has = has || feature == ApacheNativeCCSiteFeature
	}
	if m.ID == "apache-waf" || m.Delivery.Target == "apache-waf" {
		base, _, _ := strings.Cut(m.Version, "-")
		comparison, valid := CompareVersions(base, ApacheNativeCCAppVersion)
		if !valid {
			return true, errors.New("Apache 原生 CC 应用版本无法核对")
		}
		needs = comparison >= 0
	}
	if !has && !needs {
		return false, nil
	}
	if m.ID != "apache-waf" || m.Version != ApacheNativeCCAppVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "apache-waf" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 2 || m.RequiredPanelFeatures[0] != ApacheNativeBodySiteFeature || m.RequiredPanelFeatures[1] != ApacheNativeCCSiteFeature {
		return true, errors.New("Apache 原生 CC 仅允许固定2.5.0、apache-waf目标及完整请求体与 CC 站点事务处理器声明")
	}
	for _, feature := range m.RequiredPanelFeatures {
		if available == nil || !available(feature) {
			return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", feature)
		}
	}
	return true, nil
}
