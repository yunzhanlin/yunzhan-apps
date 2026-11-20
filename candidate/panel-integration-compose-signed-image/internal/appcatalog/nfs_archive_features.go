package appcatalog

import (
	"errors"
	"strings"
)

const NFSSiteArchivePreflightVersion = "1.3.2"
const NFSSiteArchivePreflightFeature = "nfs-site-archive-preflight-v1"

func validateNFSSiteArchivePreflightRequirement(manifest Manifest, available func(string) bool) (bool, error) {
	required := false
	for _, feature := range manifest.RequiredPanelFeatures {
		required = required || feature == NFSSiteArchivePreflightFeature
	}
	if manifest.ID == "nfs-manager" {
		base, _, _ := strings.Cut(manifest.Version, "-")
		if comparison, valid := CompareVersions(base, NFSSiteArchivePreflightVersion); valid && comparison >= 0 {
			required = true
		}
	}
	if !required {
		return false, nil
	}
	if manifest.ID != "nfs-manager" || manifest.Version != NFSSiteArchivePreflightVersion ||
		manifest.Delivery.Provider != "panel-module" || manifest.Delivery.Target != manifest.ID || manifest.Delivery.ManageRoute != "app-modules" ||
		len(manifest.RequiredPanelFeatures) != 1 || manifest.RequiredPanelFeatures[0] != NFSSiteArchivePreflightFeature ||
		available == nil || !available(NFSSiteArchivePreflightFeature) {
		return true, errors.New("NFS 1.3.2 须具备排队前网站引用检查和执行时保护处理器")
	}
	return true, nil
}
