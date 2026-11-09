package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

// This package revision requires the compiled 1.30.6 source allowlist together
// with separate runtime/package version accounting, never just a newer label.
const RuntimePackageVersionFeature = "runtime-package-version-v1"
const NginxRuntimePackageVersion = "1.30.6-compat1"
const NginxRuntimePackageTarget = "nginx-1.30.6"

func validateRuntimePackageRequirement(manifest Manifest, available func(string) bool) (bool, error) {
	required := false
	for _, feature := range manifest.RequiredPanelFeatures {
		required = required || feature == RuntimePackageVersionFeature
	}
	newNginx := false
	if manifest.ID == "nginx" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		comparison, valid := CompareVersions(base, "1.30.6")
		if !valid {
			return true, errors.New("Nginx 应用包版本无法核对")
		}
		newNginx = comparison >= 0
	}
	// Delivery identity is as authoritative as its visible version label. A
	// historical/foreign label must not bypass the current target's handler.
	if !required && !newNginx && manifest.Delivery.Target != NginxRuntimePackageTarget {
		return false, nil
	}
	if manifest.ID != "nginx" || manifest.Version != NginxRuntimePackageVersion || manifest.Delivery.Provider != "runtime" || manifest.Delivery.Target != NginxRuntimePackageTarget || manifest.Delivery.ManageRoute != "sites" || len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != RuntimePackageVersionFeature {
		return true, errors.New("Nginx 1.30.6 应用包须绑定固定完整版本、运行时目标和应用包版本处理器")
	}
	if available == nil || !available(RuntimePackageVersionFeature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", RuntimePackageVersionFeature)
	}
	return true, nil
}
