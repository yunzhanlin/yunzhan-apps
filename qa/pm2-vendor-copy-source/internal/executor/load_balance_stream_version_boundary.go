package executor

import (
	"errors"
	"strconv"
	"strings"

	"local/panel/internal/appcatalog"
)

var errLoadBalanceStreamIndependentLifecycle = errors.New("TCP/UDP 版本须使用独立原始签名事务；旧模块安装、配置或卸载接口不能代替新授权")

// The whole 1.9 series (including prereleases) and later versions require the
// independent original-job lifecycle. Unknown strings never become old HTTP
// authority. Empty/pre-versioned records retain their original legacy meaning.
func loadBalanceStreamIndependentLifecycle(version string) bool {
	if version == "" || version == "1.0" {
		return false
	}
	if _, valid := appcatalog.CompareVersions(version, version); !valid {
		return true
	}
	parts := strings.SplitN(version, ".", 3)
	if len(parts) != 3 {
		return true
	}
	major, e1 := strconv.ParseUint(parts[0], 10, 32)
	minor, e2 := strconv.ParseUint(parts[1], 10, 32)
	return e1 != nil || e2 != nil || major > 1 || major == 1 && minor >= 9
}

func resolveLoadBalanceStreamLegacyLifecycle(selected, original, action string, installed bool) (string, error) {
	if installed && loadBalanceStreamIndependentLifecycle(original) || action == "install" && loadBalanceStreamIndependentLifecycle(selected) {
		return "", errLoadBalanceStreamIndependentLifecycle
	}
	if action != "install" && installed {
		// Configuration or removal of an original HTTP record cannot stamp
		// the compiled implementation's newer L4 version over that record.
		if original == "" {
			return "1.0", nil
		}
		return original, nil
	}
	if loadBalanceStreamIndependentLifecycle(selected) {
		return "", errLoadBalanceStreamIndependentLifecycle
	}
	return selected, nil
}
