package appcatalog

import (
	"errors"
	"strings"
)

const NetworkIDSDurableStopVersion = "1.3.3"
const NetworkIDSDurableStopFeature = "network-ids-durable-stop-v1"

func validateNetworkIDSDurableStopRequirement(manifest Manifest, available func(string) bool) (bool, error) {
	required := false
	for _, feature := range manifest.RequiredPanelFeatures {
		required = required || feature == NetworkIDSDurableStopFeature
	}
	if manifest.ID == "network-threat-detection" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		if comparison, valid := CompareVersions(base, NetworkIDSDurableStopVersion); valid && comparison >= 0 {
			required = true
		}
	}
	if !required {
		return false, nil
	}
	if manifest.ID != "network-threat-detection" || manifest.Version != NetworkIDSDurableStopVersion ||
		manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules" ||
		len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != NetworkIDSDurableStopFeature ||
		available == nil || !available(NetworkIDSDurableStopFeature) {
		return true, errors.New("网络威胁检测 1.3.3 须具备对应的停止日志落盘处理器")
	}
	return true, nil
}
