package appcatalog

import (
	"errors"
	"fmt"
)

// The exact multi-platform OCI index was read from the primary Docker
// registry and SHA-256 verified. A tag alone is not an immutable image.
const MemcachedDigestImage = "memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf"

const MemcachedDigestFeature = "compose-memcached-digest-v1"
const MemcachedDigestVersion = "1.6.45-compat2"

// This is one closed Compose ABI, not a general exemption from the existing
// panel-module-only feature gate. The published 1.6.45-compat1 still decodes.
// The next compat2 package may claim digest pinning only with the exact template,
// image and compiled handler, in both HTTP and offline verification paths.
func validateMemcachedDigestRequirement(m Manifest, available func(string) bool) (bool, error) {
	hasFeature := false
	for _, feature := range m.RequiredPanelFeatures {
		hasFeature = hasFeature || feature == MemcachedDigestFeature
	}
	needsFeature := false
	if m.ID == "memcached" {
		// Compare the complete application revision, not a hypothetical
		// plugin 1.x version or only the upstream daemon version. Natural
		// suffix ordering makes compat2 a real update from published compat1.
		comparison, valid := CompareVersions(m.Version, MemcachedDigestVersion)
		if !valid {
			return true, errors.New("Memcached 应用版本无法核对")
		}
		needsFeature = comparison >= 0
	}
	if !hasFeature && !needsFeature {
		return false, nil
	}
	if m.ID != "memcached" || m.Version != MemcachedDigestVersion || m.Delivery.Provider != "compose" || m.Delivery.Target != "memcached-cache" || m.Delivery.ManageRoute != "docker" || m.Delivery.Isolation != "" || m.Delivery.Image != MemcachedDigestImage || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != MemcachedDigestFeature {
		return true, errors.New("Memcached 摘要版本仅接受固定完整 compat2 版本、Compose 模板、OCI 摘要和独立处理器声明")
	}
	if available == nil || !available(MemcachedDigestFeature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", MemcachedDigestFeature)
	}
	return true, nil
}
