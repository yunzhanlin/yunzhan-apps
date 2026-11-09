package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func pm2StopManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "pm2-manager", Name: "PM2 Manager", Category: "deployment", Version: PM2EvidencePreservingStopVersion, Stage: "ready", Risk: "maintained", Summary: "Owned stop fixture", Delivery: Delivery{Provider: "panel-module", Target: "pm2-manager", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{PM2EvidencePreservingStopFeature}, Capabilities: []string{"Preserving stop"}}
}

func TestPM2StopRevisionRequiresItsOwnCompiledHandler(t *testing.T) {
	m := pm2StopManifestFixture()
	if err := validatePanelRequirements(m, func(f string) bool { return f == PM2EvidencePreservingStopFeature }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(m, func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old handler authorized a new stop revision", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "old-with-new-feature", "foreign-id", "foreign-target", "route", "runtime", "compose", "foreign-feature", "foreign-id-without-feature"} {
		t.Run(scenario, func(t *testing.T) {
			v := pm2StopManifestFixture()
			switch scenario {
			case "missing":
				v.RequiredPanelFeatures = nil
			case "duplicate":
				v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, PM2EvidencePreservingStopFeature)
			case "extra":
				v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, NativeMobile133Feature)
			case "alias":
				v.Version += ".0"
			case "future":
				v.Version = "7.0.4-compat11"
			case "old-with-new-feature":
				v.Version = "7.0.4-compat9"
			case "foreign-id":
				v.ID = "daily-report"
			case "foreign-target":
				v.Delivery.Target = "daily-report"
			case "route":
				v.Delivery.ManageRoute = "security"
			case "runtime", "compose":
				v.Delivery.Provider = scenario
			case "foreign-feature":
				v.RequiredPanelFeatures = []string{NativeMobile133Feature}
			case "foreign-id-without-feature":
				v.ID, v.RequiredPanelFeatures = "daily-report", nil
			}
			if err := validatePanelRequirements(v, func(string) bool { return true }); err == nil {
				t.Fatal("borrowed or unknown PM2 stop handler accepted", scenario)
			}
		})
	}
}

func TestPM2StopRevisionRetainsExactLegacyManifestsAndPlatformScope(t *testing.T) {
	for _, version := range []string{"6", "7.0.4", "7.0.4-compat1", "7.0.4-compat2", "7.0.4-compat3", "7.0.4-compat4", "7.0.4-compat5", "7.0.4-compat6", "7.0.4-compat7", "7.0.4-compat8", "7.0.4-compat9"} {
		m := pm2StopManifestFixture()
		m.Version, m.RequiredPanelFeatures = version, nil
		if err := validatePanelRequirements(m, nil); err != nil {
			t.Fatal("original manifest lost its original acceptance", version, err)
		}
	}
	for _, version := range []string{"7.0.4.0", "7.0.4-compat9.0", "7.0.4-compat9-alias", "7.0.4-compat10", "7.0.4-compat10-alias", "7.0.5", "99.0.0"} {
		m := pm2StopManifestFixture()
		m.Version, m.RequiredPanelFeatures = version, nil
		if validatePanelRequirements(m, func(string) bool { return true }) == nil {
			t.Fatal("unbound new or aliased PM2 identity admitted", version)
		}
	}
	want := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	if panelFeatureAvailable(PM2EvidencePreservingStopFeature) != want || panelFeatureAvailable("pm2-evidence-preserving-stop-v2") {
		t.Fatal("PM2 platform or revision scope widened")
	}
}

func TestPM2StopHandlerAuthorityRemainsChecksumBound(t *testing.T) {
	m := pm2StopManifestFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/pm2-manager/7.0.4-compat10/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	if _, err := client.verifyManifestDataWithAvailability(item, raw, func(f string) bool { return f == PM2EvidencePreservingStopFeature }); err != nil {
		t.Fatal(err)
	}
	if _, err := client.verifyManifestDataWithAvailability(item, raw, func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("offline manifest admitted without its compiled handler", err)
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, err := client.verifyManifestDataWithAvailability(item, changed, func(string) bool { return true }); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("changed feature bytes bypassed signed checksum", err)
	}
	updated := sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(updated[:])
	if _, err := client.verifyManifestDataWithAvailability(item, changed, func(string) bool { return true }); err == nil {
		t.Fatal("new digest alone authorized an undeclared handler")
	}
}
