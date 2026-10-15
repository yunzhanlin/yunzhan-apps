package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func diskUsageRequirementFixture() Manifest {
	m := panelRequirementFixture()
	m.ID, m.Name, m.Version = "disk-analysis", "Disk analysis", "1.3.0"
	m.Delivery.Target = m.ID
	m.RequiredPanelFeatures = []string{DiskInodeUsageFeature}
	return m
}

func TestDiskUsagePackageRequiresExactImplementedHandlerAndScope(t *testing.T) {
	m := diskUsageRequirementFixture()
	if err := validatePanelRequirements(m, func(feature string) bool { return feature == DiskInodeUsageFeature }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(m, func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("logical-only handler authorized new package", err)
	}
	for _, kind := range []string{"missing", "empty", "wrong-feature", "duplicate", "legacy-version", "alias", "future", "other-app", "other-target", "other-route", "runtime", "compose"} {
		t.Run(kind, func(t *testing.T) {
			bad := diskUsageRequirementFixture()
			switch kind {
			case "missing":
				bad.RequiredPanelFeatures = nil
			case "empty":
				bad.RequiredPanelFeatures = []string{}
			case "wrong-feature":
				bad.RequiredPanelFeatures = []string{PlatformMaintenanceFeature}
			case "duplicate":
				bad.RequiredPanelFeatures = append(bad.RequiredPanelFeatures, DiskInodeUsageFeature)
			case "legacy-version":
				bad.Version = "1.2.0"
			case "alias":
				bad.Version = "1.3.0-compat1"
			case "future":
				bad.Version = "1.4.0"
			case "other-app":
				bad.ID = "daily-report"
				bad.Delivery.Target = bad.ID
			case "other-target":
				bad.Delivery.Target = "daily-report"
			case "other-route":
				bad.Delivery.ManageRoute = "software"
			case "runtime", "compose":
				bad.Delivery.Provider = kind
			}
			if validatePanelRequirements(bad, func(string) bool { return true }) == nil {
				t.Fatal("unbound disk implementation claim accepted", kind)
			}
		})
	}
	old := diskUsageRequirementFixture()
	old.Version = "1.2.0"
	old.RequiredPanelFeatures = nil
	if err := validatePanelRequirements(old, nil); err != nil {
		t.Fatal("legacy logical-only package broken", err)
	}
}

func TestDiskUsageManifestHashBindsHandlerAndCannotOmitItAfterRehash(t *testing.T) {
	m := diskUsageRequirementFixture()
	raw, _ := json.Marshal(m)
	hash := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/apps/disk-analysis/1.3.0/manifest.json", SHA256: hex.EncodeToString(hash[:])}
	client := Default()
	if _, err := client.verifyManifestData(item, raw); (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("actual compiled platform availability not applied", runtime.GOOS, err)
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, err := client.verifyManifestData(item, changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("modified requirement bytes borrowed old hash", err)
	}
	hash = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(hash[:])
	if _, err := client.verifyManifestData(item, changed); err == nil {
		t.Fatal("new version adopted missing implementation after rehash")
	}
}

func TestDiskUsageCompiledFeatureIsLinuxOnlyAndDoesNotGrantAnotherFeature(t *testing.T) {
	if panelFeatureAvailable(DiskInodeUsageFeature) != (runtime.GOOS == "linux") {
		t.Fatal("wrong compiled host capability")
	}
	if panelFeatureAvailable("disk-inode-usage-v0") || panelFeatureAvailable("disk-inode-usage-v2") {
		t.Fatal("prototype or future handler implicitly authorized")
	}
}
