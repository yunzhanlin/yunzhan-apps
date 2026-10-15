package appcatalog

import (
	"errors"
	"fmt"
	"strings"
)

// The exact multi-platform OCI index was read from the primary Docker
// registry and SHA-256 verified. A tag alone is not an immutable image.
const MemcachedDigestImage = "memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf"

const MemcachedDigestFeature = "compose-memcached-digest-v1"

// This is one closed Compose ABI, not a general exemption from the existing
// panel-module-only feature gate. Old immutable1.0 packages still decode.
// The future1.1 package may claim digest pinning only with the exact template,
// image and compiled handler, in both HTTP and offline verification paths.
func validateMemcachedDigestRequirement(m Manifest, available func(string) bool) (bool, error) {
	hasFeature := false
	for _, feature := range m.RequiredPanelFeatures {
		hasFeature = hasFeature || feature == MemcachedDigestFeature
	}
	needsFeature := false
	if m.ID == "memcached" {
		base, _, _ := strings.Cut(m.Version, "-")
		comparison, valid := CompareVersions(base, "1.1.0")
		if !valid {
			return true, errors.New("Memcached 应用版本无法核对")
		}
		needsFeature = comparison >= 0
	}
	if !hasFeature && !needsFeature {
		return false, nil
	}
	if m.ID != "memcached" || m.Version != "1.1.0" || m.Delivery.Provider != "compose" || m.Delivery.Target != "memcached-cache" || m.Delivery.ManageRoute != "docker" || m.Delivery.Isolation != "" || m.Delivery.Image != MemcachedDigestImage || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != MemcachedDigestFeature {
		return true, errors.New("Memcached1.1仅接受固定完整版本、Compose 模板、OCI 摘要和独立处理器声明")
	}
	if available == nil || !available(MemcachedDigestFeature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", MemcachedDigestFeature)
	}
	return true, nil
}
