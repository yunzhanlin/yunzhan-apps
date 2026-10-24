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

// Full-host jobs require original actor/installation-bound dispatch, isolated
// native workers, private receipts, cancellation and sealed recovery. The old
// website-only inode feature must not authorize this wider capability.
const DiskHostJobsFeature = "disk-host-jobs-v1"

// The2.3.1 browser tracker maintains the original30-minute activity contract
// across long-lived tabs, storage denial and BFCache. A version-only package
// cannot claim this fix on an older compiled collector.
const AnalyticsSessionFeature = "analytics-session-lifecycle-v1"

// A newer label is not authority for reversible kernel transitions, durable
// original-job journals or explicit recovery. Both manifest verification paths
// require this exact compiled Linux handler before authorizing the1.1 package.
const HardeningJournalFeature = "hardening-reversible-journal-v1"

// anti-intrusion is the signed repository identity. intrusion-prevention is
// only its fixed executor target; neither name can borrow another handler.
// The unpublished v1 prototype did not bind kernel process start time.
// It cannot authorize the final1.1 preserving transaction merely by label.
const IntrusionJournalFeature = "intrusion-preserving-journal-v2"

const WAFBoundHealthFeature = "waf-bound-health-v1"

func panelFeatureAvailable(feature string) bool {
	return runtime.GOOS == "linux" && (feature == PHPBoundedNativeBuildFeature || feature == PHPSecurity20261021Feature || feature == NativeMobileDeliveryFeature || feature == RuntimePackageVersionFeature || feature == WAFBoundHealthFeature || feature == StatisticsCursorRetirementFeature || feature == StatisticsRequestIdentityFeature || feature == StatisticsGeographyFeature || feature == PlatformMaintenanceFeature || feature == DiskInodeUsageFeature || feature == DiskHostJobsFeature || feature == MemcachedDigestFeature || feature == AnalyticsSessionFeature || feature == HardeningJournalFeature || feature == IntrusionJournalFeature)
}

func validatePanelRequirements(manifest Manifest, available func(string) bool) error {
	if handled, err := validatePHPSecurityRequirement(manifest, available); handled {
		return err
	}
	if handled, err := validateRuntimePackageRequirement(manifest, available); handled {
		return err
	}
	if handled, err := validateNativeMobileRequirement(manifest, available); handled {
		return err
	}
	if manifest.ID == "nginx-waf" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "2.5.2")
		if !valid {
			return errors.New("Nginx WAF 处理器版本无法核对")
		}
		if comparison >= 0 && (manifest.Version != "2.5.2" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != WAFBoundHealthFeature) {
			return errors.New("Nginx WAF 2.5.2 须声明固定完整版本与站点绑定的健康检查处理器")
		}
	}
	if manifest.ID == "anti-intrusion" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.1.0")
		if !valid {
			return errors.New("防入侵处理器版本无法核对")
		}
		if comparison >= 0 && (manifest.Version != "1.1.0" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != IntrusionJournalFeature) {
			return errors.New("防入侵1.1.0须声明固定完整版本与保留封禁的持久事务处理器")
		}
	}
	if manifest.ID == "system-hardening" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.1.0")
		if !valid {
			return errors.New("系统加固处理器版本无法核对")
		}
		if comparison >= 0 && (manifest.Version != "1.1.0" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != HardeningJournalFeature) {
			return errors.New("系统加固1.1.0仅接受固定完整版本及可逆持久事务处理器声明")
		}
	}
	if handled, err := validateMemcachedDigestRequirement(manifest, available); handled {
		return err
	}
	if manifest.ID == "website-analytics" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "2.3.1")
		if !valid {
			return errors.New("浏览器分析会话处理器版本无法核对")
		}
		if comparison >= 0 && (manifest.Version != "2.3.1" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != AnalyticsSessionFeature) {
			return errors.New("浏览器分析2.3.1仅接受固定完整版本及有界会话生命周期处理器声明")
		}
	}
	if manifest.ID == "disk-analysis" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.3.0")
		if !valid {
			return errors.New("磁盘分析版本无法核对")
		}
		if comparison >= 0 {
			switch manifest.Version {
			case "1.3.0":
				if len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != DiskInodeUsageFeature {
					return errors.New("磁盘分析1.3仅接受 inode 分配块、有界不跟随链接处理器声明")
				}
			case "1.4.0":
				inode, host := false, false
				for _, f := range manifest.RequiredPanelFeatures {
					inode = inode || f == DiskInodeUsageFeature
					host = host || f == DiskHostJobsFeature
				}
				if len(manifest.RequiredPanelFeatures) != 2 || !inode || !host {
					return errors.New("磁盘分析1.4须同时声明 inode 空间与独立全盘后台任务处理器")
				}
			default:
				return errors.New("磁盘分析新格式仅允许固定完整版本1.3.0或1.4.0")
			}
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
		if feature == WAFBoundHealthFeature && (manifest.ID != "nginx-waf" || manifest.Version != "2.5.2" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "security") {
			return errors.New("站点绑定的健康检查处理器仅属于 Nginx WAF 2.5.2 的固定安全管理目标")
		}
		if feature == IntrusionJournalFeature && (manifest.ID != "anti-intrusion" || manifest.Version != "1.1.0" || manifest.Delivery.Target != "intrusion-prevention" || manifest.Delivery.ManageRoute != "security") {
			return errors.New("防入侵事务处理器仅属于anti-intrusion1.1.0的固定安全管理目标")
		}
		if feature == HardeningJournalFeature && (manifest.ID != "system-hardening" || manifest.Version != "1.1.0" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "security") {
			return errors.New("可逆加固事务处理器要求仅属于system-hardening1.1.0")
		}
		if feature == AnalyticsSessionFeature && (manifest.ID != "website-analytics" || manifest.Version != "2.3.1" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules") {
			return errors.New("浏览器会话处理器要求仅属于website-analytics2.3.1")
		}
		if feature == DiskInodeUsageFeature && (manifest.ID != "disk-analysis" || manifest.Version != "1.3.0" && manifest.Version != "1.4.0" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules") {
			return errors.New("inode 空间处理器要求仅属于disk-analysis1.3.0或1.4.0")
		}
		if feature == DiskHostJobsFeature && (manifest.ID != "disk-analysis" || manifest.Version != "1.4.0" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules") {
			return errors.New("全盘后台任务处理器仅属于disk-analysis1.4.0")
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
