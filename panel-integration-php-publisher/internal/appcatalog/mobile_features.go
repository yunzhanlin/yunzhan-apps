package appcatalog

import (
	"errors"
	"fmt"
)

const NativeMobileVersion = "1.3.2"
const NativeMobileDeliveryFeature = "mobile-native-delivery-v132"

// Published legacy endpoints keep their exact identity. A lower or equivalent
// semantic version is not proof of an independently reviewed native delivery.
func NativeMobileUpdateVersionAllowed(version string) bool {
	switch version {
	case "1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", NativeMobileVersion:
		return true
	}
	return false
}

// Native client sources are not a server-handler upgrade. Only the compiled
// fixed delivery metadata may authorize the new application revision; legacy
// signed1.0 through1.3.0 manifests keep their original acceptance contract.
func validateNativeMobileRequirement(m Manifest, available func(string) bool) (bool, error) {
	has, needs := false, false
	for _, f := range m.RequiredPanelFeatures {
		has = has || f == NativeMobileDeliveryFeature
	}
	if m.ID == "mobile" || m.Delivery.Target == "mobile-pwa" {
		needs = m.Version == NativeMobileVersion || !NativeMobileUpdateVersionAllowed(m.Version)
	}
	if !has && !needs {
		return false, nil
	}
	if m.ID != "mobile" || m.Version != NativeMobileVersion || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "mobile-pwa" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != NativeMobileDeliveryFeature {
		return true, errors.New("移动端新交付仅允许固定1.3.2、mobile-pwa目标及独立编译的原生交付处理器")
	}
	if available == nil || !available(NativeMobileDeliveryFeature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", NativeMobileDeliveryFeature)
	}
	return true, nil
}
