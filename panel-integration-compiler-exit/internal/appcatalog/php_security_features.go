package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

const PHPSecurity20261021Feature = "php-security-20261021-v1"

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
		has = has || f == PHPSecurity20261021Feature
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
	if !scoped || m.Version != version+"-compat1" || m.Delivery.Provider != "runtime" || m.Delivery.Target != "php-"+version || m.Delivery.ManageRoute != "runtimes" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != PHPSecurity20261021Feature {
		return true, errors.New("PHP 安全更新仅允许四个固定官方补丁、对应分支目标、完整包版本及独立安全准入处理器")
	}
	if available == nil || !available(PHPSecurity20261021Feature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", PHPSecurity20261021Feature)
	}
	return true, nil
}
