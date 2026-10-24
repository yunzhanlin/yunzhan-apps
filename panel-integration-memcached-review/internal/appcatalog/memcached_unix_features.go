package appcatalog

import (
	"errors"
	"fmt"
)

const MemcachedUnixVersion = "1.6.45-compat4"
const MemcachedUnixFeature = "compose-memcached-unix-v1"

// Semantic identity, not signature verification or execution authority. The
// abandoned unpublished TCP/internal-network prototype cannot borrow this
// socket-only contract simply by changing its label or version.
func IsMemcachedUnixManifest(m Manifest) bool {
	if m.ID != "memcached" || m.Version != MemcachedUnixVersion || m.Delivery.Provider != "compose" || m.Delivery.Target != "memcached-cache" || m.Delivery.ManageRoute != "docker" || m.Delivery.Isolation != "" || m.Delivery.Image != MemcachedDigestImage || len(m.RequiredPanelFeatures) != 2 {
		return false
	}
	digest, unix := false, false
	for _, f := range m.RequiredPanelFeatures {
		digest = digest || f == MemcachedDigestFeature
		unix = unix || f == MemcachedUnixFeature
	}
	return digest && unix
}

func validateMemcachedUnixRequirement(m Manifest, available func(string) bool) (bool, error) {
	claimed := false
	for _, f := range m.RequiredPanelFeatures {
		claimed = claimed || f == MemcachedUnixFeature
	}
	if m.ID == "memcached" {
		comparison, valid := CompareVersions(m.Version, MemcachedUnixVersion)
		if !valid {
			return true, errors.New("Memcached Unix Socket 包版本无法核对")
		}
		claimed = claimed || comparison >= 0
	}
	if !claimed {
		return false, nil
	}
	if !IsMemcachedUnixManifest(m) {
		return true, errors.New("Memcached Unix Socket 仅接受固定完整 compat4、固定 OCI 镜像及两个独立处理器声明")
	}
	for _, f := range []string{MemcachedDigestFeature, MemcachedUnixFeature} {
		if available == nil || !available(f) {
			return true, fmt.Errorf("面板处理器不支持 %s；未安装或更新应用", f)
		}
	}
	return true, nil
}
