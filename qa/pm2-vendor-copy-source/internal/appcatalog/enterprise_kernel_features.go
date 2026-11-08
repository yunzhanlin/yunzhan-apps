package appcatalog

import (
	"errors"
	"strings"
)

// Website1.5's ABI must not grant another application control of its journal.
// The enterprise ABI adds exact app identities and one shared ownership chain.
const EnterpriseKernelFeature = "enterprise-integrity-kernel-ownership-v1"

func validateEnterpriseKernelRequirement(m Manifest, available func(string) bool) (bool, error) {
	mentions := false
	for _, feature := range m.RequiredPanelFeatures {
		mentions = mentions || feature == EnterpriseKernelFeature
	}
	if m.ID != "enterprise-tamper-proof" {
		if mentions {
			return true, errors.New("企业内核保护处理器不能授权其他应用")
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, "1.5.0")
	if !mentions && valid && comparison < 0 {
		return false, nil
	}
	if m.Version != "1.5.0" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != EnterpriseKernelFeature {
		return true, errors.New("企业内核写保护须声明精确1.5.0应用、独立身份与跨应用保护所有权；旧网站ABI不能借用")
	}
	if available == nil || !available(EnterpriseKernelFeature) {
		return true, errors.New("请先升级面板：缺少企业内核写保护及跨应用所有权处理器")
	}
	return true, nil
}
