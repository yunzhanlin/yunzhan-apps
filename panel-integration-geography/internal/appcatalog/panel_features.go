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
const StatisticsRequestIdentityFeature = "statistics-request-identity-v1"

// v2 requires the fixed resource-bounded cache reader and restart fallback;
// the unpublished v1 prototype must not authorize the final2.6 package.
const StatisticsGeographyFeature = "statistics-geodata-v2"

// Separate maintenance grants and original native journals; old health-only
// handlers and the unversioned prototype must not authorize the1.3 package.
const PlatformMaintenanceFeature = "platform-maintenance-v1"

// Includes bounded FD-relative nofollow traversal, inode-deduplicated block
// accounting and truthful unknown/partial reporting. Logical-only handlers do
// not authorize the 1.3 package merely by accepting a newer version string.
const DiskInodeUsageFeature = "disk-inode-usage-v1"

func panelFeatureAvailable(feature string) bool {
	return runtime.GOOS == "linux" && (feature == StatisticsCursorRetirementFeature || feature == StatisticsRequestIdentityFeature || feature == StatisticsGeographyFeature || feature == PlatformMaintenanceFeature || feature == DiskInodeUsageFeature)
}

func validatePanelRequirements(manifest Manifest, available func(string) bool) error {
	if manifest.ID == "disk-analysis" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.3.0")
		if !valid {
			return errors.New("磁盘分析版本无法核对")
		}
		if comparison >= 0 && (manifest.Version != "1.3.0" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != DiskInodeUsageFeature) {
			return errors.New("磁盘分析1.3仅接受固定完整版本及 inode 分配块、有界不跟随链接处理器声明")
		}
	}
	if manifest.ID == "platform-ops" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.3.0")
		if !valid {
			return errors.New("维护应用版本无法核对")
		}
		if comparison >= 0 {
			found := false
			for _, feature := range manifest.RequiredPanelFeatures {
				found = found || feature == PlatformMaintenanceFeature
			}
			if manifest.Version != "1.3.0" || !found {
				return errors.New("维护1.3仅接受固定完整版本及独立授权、原生原回执处理器声明")
			}
		}
	}
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
		identity, valid := CompareVersions(base, "2.5.0")
		if !valid {
			return errors.New("统计请求标识版本无法核对")
		}
		if identity >= 0 {
			found := false
			for _, feature := range manifest.RequiredPanelFeatures {
				found = found || feature == StatisticsRequestIdentityFeature
			}
			if !found {
				return errors.New("统计2.5缺少必需的请求标识、迁移恢复及压缩归档处理器声明")
			}
		}
		geography, valid := CompareVersions(base, "2.6.0")
		if !valid {
			return errors.New("统计地域版本无法核对")
		}
		if geography >= 0 {
			found := false
			for _, feature := range manifest.RequiredPanelFeatures {
				found = found || feature == StatisticsGeographyFeature
			}
			if !found {
				return errors.New("统计2.6缺少独立签名的离线地域数据处理器声明")
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
		if feature == DiskInodeUsageFeature && (manifest.ID != "disk-analysis" || manifest.Version != "1.3.0" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules") {
			return errors.New("inode 空间处理器要求仅属于disk-analysis1.3.0")
		}
		if feature == PlatformMaintenanceFeature && (manifest.ID != "platform-ops" || manifest.Version != "1.3.0" || manifest.Delivery.Target != manifest.ID) {
			return errors.New("独立维护处理器要求仅属于platform-ops1.3.0")
		}
		if (feature == StatisticsCursorRetirementFeature || feature == StatisticsRequestIdentityFeature || feature == StatisticsGeographyFeature) && (manifest.ID != "website-statistics-v2" || manifest.Delivery.Target != manifest.ID) {
			return errors.New("统计历史处理器要求不属于该应用")
		}
		if !available(feature) {
			return fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", feature)
		}
	}
	return nil
}
