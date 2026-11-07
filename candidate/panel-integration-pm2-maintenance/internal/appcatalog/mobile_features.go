package appcatalog

import (
	"errors"
	"fmt"
)

const NativeMobile132Version = "1.3.2"
const NativeMobile132Feature = "mobile-native-delivery-v132"
const NativeMobile133Version = "1.3.3"
const NativeMobile133Feature = "mobile-native-delivery-v133"
const NativeMobileVersion = NativeMobile133Version
const NativeMobileDeliveryFeature = NativeMobile133Feature

// Keep previously published, signed native queues bound to their own identity
// when a newer delivery becomes current. This is an exact allowlist, not a
// semantic-version range or authority to adopt an unsigned native request.
func NativeMobileSignedVersion(version string) bool {
	return version == NativeMobile132Version || version == NativeMobile133Version || version == NativeMobileVersion
}

func nativeMobileFeatureForVersion(version string) string {
	if version == NativeMobile132Version {
		return NativeMobile132Feature
	}
	if version == NativeMobile133Version {
		return NativeMobile133Feature
	}
	if version == NativeMobileVersion {
		return NativeMobileDeliveryFeature
	}
	return ""
}

// Published legacy endpoints keep their exact identity. A lower or equivalent
// semantic version is not proof of an independently reviewed native delivery.
func NativeMobileUpdateVersionAllowed(version string) bool {
	if NativeMobileSignedVersion(version) {
		return true
	}
	switch version {
	case "1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0":
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
		has = has || f == NativeMobileDeliveryFeature || f == NativeMobile132Feature || f == NativeMobile133Feature
	}
	if m.ID == "mobile" || m.Delivery.Target == "mobile-pwa" {
		needs = NativeMobileSignedVersion(m.Version) || !NativeMobileUpdateVersionAllowed(m.Version)
	}
	if !has && !needs {
		return false, nil
	}
	feature := nativeMobileFeatureForVersion(m.Version)
	if m.ID != "mobile" || feature == "" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != "mobile-pwa" || m.Delivery.ManageRoute != "app-modules" || len(m.RequiredPanelFeatures) != 1 || m.RequiredPanelFeatures[0] != feature {
		return true, errors.New("移动端原生交付需要已发布的精确版本、mobile-pwa目标及对应的独立编译处理器")
	}
	if available == nil || !available(feature) {
		return true, fmt.Errorf("面板处理器不支持 %s；请先升级面板，未安装或更新应用", feature)
	}
	return true, nil
}
