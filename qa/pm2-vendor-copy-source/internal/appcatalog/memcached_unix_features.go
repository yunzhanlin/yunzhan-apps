package appcatalog

import (
	"errors"
	"fmt"
)

const MemcachedUnixVersion = "1.6.45-compat4"
const MemcachedUnixFeature = "compose-memcached-unix-v1"

// The unpublished cache-only candidates did not implement the stopped-CID
// retirement journal. Their Unix capability cannot authorize that functionality.
// Require this independently compiled Core/Root handler before first publication.
const MemcachedUnixRetirementFeature = "compose-memcached-retirement-v1"

// Semantic identity, not signature verification or execution authority. The
// abandoned unpublished TCP/internal-network prototype cannot borrow this
// socket-only contract simply by changing its label or version.
func IsMemcachedUnixManifest(m Manifest) bool {
	if m.ID != "memcached" || m.Version != MemcachedUnixVersion || m.Delivery.Provider != "compose" || m.Delivery.Target != "memcached-cache" || m.Delivery.ManageRoute != "docker" || m.Delivery.Isolation != "" || m.Delivery.Image != MemcachedDigestImage || len(m.RequiredPanelFeatures) != 3 {
		return false
	}
	digest, unix, retirement := false, false, false
	for _, f := range m.RequiredPanelFeatures {
		digest = digest || f == MemcachedDigestFeature
		unix = unix || f == MemcachedUnixFeature
		retirement = retirement || f == MemcachedUnixRetirementFeature
	}
	return digest && unix && retirement
}

func validateMemcachedUnixRequirement(m Manifest, available func(string) bool) (bool, error) {
	claimed := false
	for _, f := range m.RequiredPanelFeatures {
		claimed = claimed || f == MemcachedUnixFeature || f == MemcachedUnixRetirementFeature
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
		return true, errors.New("Memcached Unix Socket 仅接受固定完整 compat4、固定 OCI 镜像及 Socket、摘要和安全移除三个独立处理器声明")
	}
	// Docker socket existence is only liveness, not the real peer-bound
	// workspace readiness probe. Match the distributor's closed contract;
	// even an officially signed package cannot redefine retention or make a
	// networkless instance claim a legacy TCP/Compose health handler.
	if m.Health != (Health{Probe: "panel-api", Target: "memcached-unix-workspace"}) ||
		m.Uninstall != (Uninstall{PreserveData: true, ReferenceCheck: true}) {
		return true, errors.New("Memcached Unix Socket 必须使用真实工作区健康核验并保留原归属记录与引用检查")
	}
	for _, f := range []string{MemcachedDigestFeature, MemcachedUnixFeature, MemcachedUnixRetirementFeature} {
		if available == nil || !available(f) {
			return true, fmt.Errorf("面板处理器不支持 %s；未安装或更新应用", f)
		}
	}
	return true, nil
}
