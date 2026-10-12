package appcatalog

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Requirements live in the checksum-bound manifest, NOT only the catalog's
// marketing capability strings. Old strict manifest decoders reject this
// field, so an old handler cannot merely publish a newer installed version.
// Both HTTP-side pulls and executor-side offline verification use this gate.
const StatisticsCursorRetirementFeature = "statistics-cursor-retirement-v1"

func panelFeatureAvailable(feature string) bool {
	return runtime.GOOS == "linux" && feature == StatisticsCursorRetirementFeature
}

func validatePanelRequirements(manifest Manifest, available func(string) bool) error {
	if manifest.ID == "website-statistics-v2" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "2.4.1")
		if !valid {
			return errors.New("统计历史处理器版本无法核对，未安装或更新应用")
		}
		if comparison >= 0 {
			found := false
			for _, feature := range manifest.RequiredPanelFeatures {
				found = found || feature == StatisticsCursorRetirementFeature
			}
			if !found {
				return errors.New("统计历史新版本缺少必需的面板处理器声明，未安装或更新应用")
			}
		}
	}
	if len(manifest.RequiredPanelFeatures) == 0 {
		return nil
	}
	if len(manifest.RequiredPanelFeatures) > 8 || manifest.Delivery.Provider != "panel-module" || available == nil {
		return errors.New("应用面板处理器要求无效")
	}
	seen := map[string]bool{}
	for _, feature := range manifest.RequiredPanelFeatures {
		if !idPattern.MatchString(feature) || seen[feature] {
			return errors.New("应用面板处理器要求无效或重复")
		}
		seen[feature] = true
		if feature == StatisticsCursorRetirementFeature && (manifest.ID != "website-statistics-v2" || manifest.Delivery.Target != manifest.ID) {
			return errors.New("统计历史处理器要求不属于该应用")
		}
		if !available(feature) {
			return fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", feature)
		}
	}
	return nil
}
