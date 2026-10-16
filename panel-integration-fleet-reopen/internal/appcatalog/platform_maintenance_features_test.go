package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func maintenanceRequirementFixture() Manifest {
	m := panelRequirementFixture()
	m.ID, m.Name, m.Version = "platform-ops", "Platform Ops", "1.3.0"
	m.Delivery.Target = m.ID
	m.RequiredPanelFeatures = []string{PlatformMaintenanceFeature}
	return m
}

func TestPlatformMaintenancePackageRequiresVersionedImplementationAndScope(t *testing.T) {
	m := maintenanceRequirementFixture()
	if e := validatePanelRequirements(m, func(feature string) bool { return feature == PlatformMaintenanceFeature }); e != nil {
		t.Fatal(e)
	}
	if e := validatePanelRequirements(m, func(string) bool { return false }); e == nil || !strings.Contains(e.Error(), "请先升级面板") {
		t.Fatal("health-only/prototype handler authorized new app", e)
	}
	for _, scenario := range []string{"missing", "wrong-feature", "duplicate", "old-version", "alias", "future", "other-app", "other-target", "runtime"} {
		bad := maintenanceRequirementFixture()
		switch scenario {
		case "missing":
			bad.RequiredPanelFeatures = nil
		case "wrong-feature":
			bad.RequiredPanelFeatures = []string{StatisticsRequestIdentityFeature}
		case "duplicate":
			bad.RequiredPanelFeatures = []string{PlatformMaintenanceFeature, PlatformMaintenanceFeature}
		case "old-version":
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
		case "runtime":
			bad.Delivery.Provider = "runtime"
		}
		if validatePanelRequirements(bad, func(string) bool { return true }) == nil {
			t.Fatal("unbound maintenance admitted", scenario)
		}
	}
	legacy := maintenanceRequirementFixture()
	legacy.Version, legacy.RequiredPanelFeatures = "1.2.0", nil
	if e := validatePanelRequirements(legacy, nil); e != nil {
		t.Fatal("old readonly app no longer decodes", e)
	}
}

func TestPlatformMaintenanceManifestBytesCannotBorrowNewHandlerClaim(t *testing.T) {
	m := maintenanceRequirementFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/platform-ops/1.3.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	if _, e := client.verifyManifestData(item, raw); (e == nil) != (runtime.GOOS == "linux") {
		t.Fatal("actual compiled OS availability ignored", e)
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, e := client.verifyManifestData(item, changed); e == nil || !strings.Contains(e.Error(), "SHA-256") {
		t.Fatal("unbound manifest requirements accepted", e)
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	if _, e := client.verifyManifestData(item, changed); e == nil {
		t.Fatal("new app accepted omitted implementation requirement")
	}
}
