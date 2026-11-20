package appcatalog

import (
	"errors"
	"strings"
)

const NetworkIDSIndependentArchiveVersion = "1.3.4"
const NetworkIDSIndependentArchiveFeature = "network-ids-independent-archive-v1"

func validateNetworkIDSIndependentArchiveRequirement(manifest Manifest, available func(string) bool) (bool, error) {
	required := false
	for _, feature := range manifest.RequiredPanelFeatures {
		required = required || feature == NetworkIDSIndependentArchiveFeature
	}
	if manifest.ID == "network-threat-detection" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		if comparison, valid := CompareVersions(base, NetworkIDSIndependentArchiveVersion); valid && comparison >= 0 {
			required = true
		}
	}
	if !required {
		return false, nil
	}
	if manifest.ID != "network-threat-detection" || manifest.Version != NetworkIDSIndependentArchiveVersion ||
		manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules" ||
		len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != NetworkIDSIndependentArchiveFeature ||
		available == nil || !available(NetworkIDSIndependentArchiveFeature) {
		return true, errors.New("网络威胁检测 1.3.4 须具备对应的独立私有归档处理器")
	}
	return true, nil
}
