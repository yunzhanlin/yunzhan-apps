package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

const PHPSecurity20261021Feature = "php-security-20261021-v1"

// compat2 must not be installed by a security-catalog-only handler: the
// fileinfo byte-exact representation, finite native unit/cgroup budget and
// original-attempt-preserving OOM protocol are required as well. Historical
// compat1 identities remain readable, never silently promoted to compat2.
const PHPBoundedNativeBuildFeature = "php-bounded-native-build-v1"

func phpSecurityBinding(id string) (string, bool) {
	switch id {
	case "php-82":
		return "8.2.35", true
	case "php-83":
		return "8.3.36", true
	case "php-84":
		return "8.4.27", true
	case "php-85":
		return "8.5.12", true
	}
	return "", false
}

// A patch label is not authority to install an arbitrary source or to claim
// that existing site workers have switched. Historical packages remain
// readable; only the four exact new packages require this compiled admission.
func validatePHPSecurityRequirement(m Manifest, available func(string) bool) (bool, error) {
	has := false
	for _, f := range m.RequiredPanelFeatures {
		has = has || f == PHPSecurity20261021Feature || f == PHPBoundedNativeBuildFeature
	}
	version, scoped := phpSecurityBinding(m.ID)
	targetScoped := false
	for _, id := range []string{"php-82", "php-83", "php-84", "php-85"} {
		v, _ := phpSecurityBinding(id)
		targetScoped = targetScoped || m.Delivery.Target == "php-"+v
	}
	needs := false
	if scoped {
		base, _, _ := strings.Cut(m.Version, "-")
		comparison, valid := CompareVersions(base, version)
		if !valid {
			return true, errors.New("PHP 安全应用包版本无法核对")
		}
		needs = comparison >= 0
	}
	if !has && !needs && !targetScoped {
		return false, nil
	}
	if !scoped || m.Delivery.Provider != "runtime" || m.Delivery.Target != "php-"+version || m.Delivery.ManageRoute != "runtimes" {
		return true, errors.New("PHP 安全更新仅允许四个固定官方补丁、对应分支目标、完整包版本及独立安全准入处理器")
	}
	required := []string{PHPSecurity20261021Feature}
	switch m.Version {
	case version + "-compat1":
		if len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != PHPSecurity20261021Feature {
			return true, errors.New("PHP 历史 compat1 包须保留原始独立安全处理器声明，不能借用新构建能力")
		}
	case version + "-compat2":
		security, bounded := false, false
		for _, feature := range m.RequiredPanelFeatures {
			security = security || feature == PHPSecurity20261021Feature
			bounded = bounded || feature == PHPBoundedNativeBuildFeature
		}
		if len(m.RequiredPanelFeatures) != 2 || !security || !bounded {
			return true, errors.New("PHP compat2 包须同时声明固定安全补丁及有界低内存原生构建处理器，未安装或更新应用")
		}
		required = append(required, PHPBoundedNativeBuildFeature)
	default:
		return true, errors.New("PHP 安全更新仅允许固定完整包版本 compat1 或具备独立构建准入的 compat2")
	}
	for _, feature := range required {
		if available == nil || !available(feature) {
			return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", feature)
		}
	}
	return true, nil
}
