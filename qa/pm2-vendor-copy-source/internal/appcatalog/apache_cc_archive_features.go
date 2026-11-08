package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

const ApacheCCLogArchiveFeature = "apache-cc-log-archive-v1"
const ApacheCCLogArchiveAppVersion = "2.5.1"

func validateApacheCCArchiveRequirement(m Manifest, available func(string) bool) (bool, error) {
	has, needs := false, false
	for _, feature := range m.RequiredPanelFeatures {
		has = has || feature == ApacheCCLogArchiveFeature
	}
	if m.ID == "apache-waf" || m.Delivery.Target == "apache-waf" {
		base, _, _ := strings.Cut(m.Version, "-")
		comparison, valid := CompareVersions(base, ApacheCCLogArchiveAppVersion)
		if !valid {
			return true, errors.New("Apache CC 归档应用版本无法核对")
		}
		needs = comparison >= 0
	}
	if !has && !needs {
		return false, nil
	}
	if m.ID != "apache-waf" || m.Version != ApacheCCLogArchiveAppVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "apache-waf" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 3 || m.RequiredPanelFeatures[0] != ApacheNativeBodySiteFeature || m.RequiredPanelFeatures[1] != ApacheNativeCCSiteFeature || m.RequiredPanelFeatures[2] != ApacheCCLogArchiveFeature {
		return true, errors.New("Apache CC 归档仅允许固定2.5.1及完整请求体、CC、归档三个处理器声明")
	}
	for _, feature := range m.RequiredPanelFeatures {
		if available == nil || !available(feature) {
			return true, fmt.Errorf("面板处理器不支持 %s；未授权 CC 归档应用升级", feature)
		}
	}
	return true, nil
}
