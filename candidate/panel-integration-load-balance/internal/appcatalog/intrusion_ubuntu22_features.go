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

func validateIntrusionUbuntu22Requirement(m Manifest, available func(string) bool) (bool, error) {
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "1.1.1")
	relevant := slices.Contains(m.RequiredPanelFeatures, IntrusionUbuntu22Feature) || m.ID == "anti-intrusion" && valid && comparison >= 0
	if !relevant {
		return false, nil
	}
	if m.ID != "anti-intrusion" || m.Version != "1.1.1" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "intrusion-prevention" || m.Delivery.ManageRoute != "security" || !slices.Equal(m.RequiredPanelFeatures, []string{IntrusionJournalFeature, IntrusionUbuntu22Feature}) {
		return true, errors.New("防入侵1.1.1须绑定固定安全目标、保留封禁事务及已核对的0.11.2处理器")
	}
	if available == nil || !available(IntrusionJournalFeature) || !available(IntrusionUbuntu22Feature) {
		return true, errors.New("请先升级面板：缺少防入侵1.1.1所需的已核对0.11.2与旧事务兼容处理器")
	}
	return true, nil
}
