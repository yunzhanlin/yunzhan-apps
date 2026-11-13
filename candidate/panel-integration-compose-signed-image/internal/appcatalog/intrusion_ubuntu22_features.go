package appcatalog

import (
	"errors"
	"slices"
	"strings"
)

// The exact 0.11.2 adapter and byte-preserving 1.1.0 journal reader ship in
// the signed Linux programme. Existing journal-v2 handlers cannot adopt this
// package by accepting a new label or by changing catalogue compatibility.
const IntrusionUbuntu22Feature = "intrusion-upstream0112-v1"
const IntrusionDebian12Feature = "intrusion-debian12-v1"
const IntrusionDebian12Version = "1.1.2"

var intrusionDebian12OS = []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04"}
var intrusionDebian12Architectures = []string{"amd64", "arm64"}

func IntrusionDebian12Supports(platform, architecture string) bool {
	return slices.Contains(intrusionDebian12OS, platform) && slices.Contains(intrusionDebian12Architectures, architecture)
}

func validateIntrusionUbuntu22Requirement(m Manifest, available func(string) bool) (bool, error) {
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "1.1.1")
	relevant := slices.Contains(m.RequiredPanelFeatures, IntrusionUbuntu22Feature) ||
		slices.Contains(m.RequiredPanelFeatures, IntrusionDebian12Feature) || m.ID == "anti-intrusion" && valid && comparison >= 0
	if !relevant {
		return false, nil
	}
	if m.ID != "anti-intrusion" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "intrusion-prevention" || m.Delivery.ManageRoute != "security" {
		return true, errors.New("防入侵签名包须绑定固定安全处理器")
	}
	required := []string{IntrusionJournalFeature, IntrusionUbuntu22Feature}
	switch m.Version {
	case "1.1.1":
	case IntrusionDebian12Version:
		required = append(required, IntrusionDebian12Feature)
		if !slices.Equal(m.Compatibility.OS, intrusionDebian12OS) ||
			!slices.Equal(m.Compatibility.Architectures, intrusionDebian12Architectures) {
			return true, errors.New("防入侵 1.1.2 的签名系统和架构清单不匹配")
		}
	default:
		return true, errors.New("防入侵签名包版本未支持")
	}
	if !slices.Equal(m.RequiredPanelFeatures, required) {
		return true, errors.New("防入侵签名包须声明该版本完整处理器")
	}
	for _, feature := range required {
		if available == nil || !available(feature) {
			return true, errors.New("请先升级面板，当前面板缺少防入侵所需处理器")
		}
	}
	return true, nil
}
