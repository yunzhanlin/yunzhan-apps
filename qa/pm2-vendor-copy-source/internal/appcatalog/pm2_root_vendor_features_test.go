package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func pm2RootVendorManifestFixture() Manifest {
	m := pm2StopManifestFixture()
	m.Version, m.RequiredPanelFeatures = PM2RootVendorVersion, []string{PM2RootVendorFeature}
	return m
}

func pm2RootVendorAvailable(feature string) bool {
	return feature == PM2RootVendorFeature || feature == PM2EvidencePreservingStopFeature
}

func TestPM2RootVendorRequiresIndependentCopyAndOriginalStopHandler(t *testing.T) {
	m := pm2RootVendorManifestFixture()
	if err := validatePanelRequirements(m, pm2RootVendorAvailable); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{PM2RootVendorFeature, PM2EvidencePreservingStopFeature} {
		if err := validatePanelRequirements(m, func(f string) bool { return pm2RootVendorAvailable(f) && f != missing }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("manifest borrowed an unavailable implementation", missing, err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "legacy", "foreign-id", "foreign-target", "route", "runtime", "old-feature"} {
		t.Run(scenario, func(t *testing.T) {
			v := pm2RootVendorManifestFixture()
			switch scenario {
			case "missing":
				v.RequiredPanelFeatures = nil
			case "duplicate":
				v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, PM2RootVendorFeature)
			case "extra":
				v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, PM2EvidencePreservingStopFeature)
			case "alias":
				v.Version += ".0"
			case "future":
				v.Version = "7.0.4-compat12"
			case "legacy":
				v.Version = PM2EvidencePreservingStopVersion
			case "foreign-id":
				v.ID = "daily-report"
			case "foreign-target":
				v.Delivery.Target = "daily-report"
			case "route":
				v.Delivery.ManageRoute = "security"
			case "runtime":
				v.Delivery.Provider = "runtime"
			case "old-feature":
				v.RequiredPanelFeatures = []string{PM2EvidencePreservingStopFeature}
			}
			if err := validatePanelRequirements(v, func(string) bool { return true }); err == nil {
				t.Fatal("borrowed, missing or aliased Root vendor implementation accepted", scenario)
			}
		})
	}
}

func TestPM2RootVendorRetainsCompat10ExactAuthorityAndPlatformScope(t *testing.T) {
	old := pm2StopManifestFixture()
	if err := validatePanelRequirements(old, func(f string) bool { return f == PM2EvidencePreservingStopFeature }); err != nil {
		t.Fatal("old immutable stop manifest changed", err)
	}
	if err := validatePanelRequirements(old, func(f string) bool { return f == PM2RootVendorFeature }); err == nil {
		t.Fatal("Root vendor feature substituted for the original stop handler")
	}
	want := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	if panelFeatureAvailable(PM2RootVendorFeature) != want || panelFeatureAvailable("pm2-root-vendor-v2") {
		t.Fatal("Root vendor platform or feature revision scope changed")
	}
}

func TestPM2RootVendorManifestRequiresSignedBytesAndBothCompiledHandlers(t *testing.T) {
	m := pm2RootVendorManifestFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/pm2-manager/7.0.4-compat11/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	if _, err := client.verifyManifestDataWithAvailability(item, raw, pm2RootVendorAvailable); err != nil {
		t.Fatal(err)
	}
	if _, err := client.verifyManifestDataWithAvailability(item, raw, func(f string) bool { return f == PM2EvidencePreservingStopFeature }); err == nil {
		t.Fatal("offline pull admitted an absent Root copy implementation")
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, err := client.verifyManifestDataWithAvailability(item, changed, pm2RootVendorAvailable); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("changed implementation declaration bypassed signed checksum", err)
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	if _, err := client.verifyManifestDataWithAvailability(item, changed, pm2RootVendorAvailable); err == nil {
		t.Fatal("a new digest alone authorized an undeclared Root copy implementation")
	}
}
