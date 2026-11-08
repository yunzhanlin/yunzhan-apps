package appcatalog

import (
	"errors"
	"strings"
)

const IntegrityKernelFeature = "integrity-kernel-inode-journal-v1"

func validateIntegrityKernelRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == IntegrityKernelFeature
	}
	if m.ID != "website-tamper-proof" {
		if mentions {
			return true, errors.New("内核 inode 写保护处理器仅属于网站防篡改 1.5.0")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "1.5.0")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "1.5.0" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != IntegrityKernelFeature {
		return true, errors.New("内核写保护须固定完整网站防篡改 1.5.0，并声明原生 inode、持久任务和解除处理器")
	}
	if available == nil || !available(IntegrityKernelFeature) {
		return true, errors.New("请先升级面板：缺少可恢复内核写保护处理器；旧版本标签不能取得 Root 控制能力")
	}
	return true, nil
}
