package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func runtimePackageManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "nginx", Name: "Nginx", Category: "deployment", Version: NginxRuntimePackageVersion, Stage: "ready", Risk: "maintained", Summary: "Fixed runtime/package-version authority model, not installed app acceptance", Capabilities: []string{"install"}, Delivery: Delivery{Provider: "runtime", Target: NginxRuntimePackageTarget, ManageRoute: "sites"}, RequiredPanelFeatures: []string{RuntimePackageVersionFeature}}
}

func TestRuntimePackageFeatureRequiresActualCompiledLinuxHandler(t *testing.T) {
	m := runtimePackageManifestFixture()
	if err := validatePanelRequirements(m, func(feature string) bool { return feature == RuntimePackageVersionFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(m, available); err == nil || !strings.Contains(err.Error(), RuntimePackageVersionFeature) {
			t.Fatal("old handler accepted revision claim", err)
		}
	}
	if panelFeatureAvailable(RuntimePackageVersionFeature) != (runtime.GOOS == "linux") {
		t.Fatal("feature advertised on an unsupported operating system")
	}
}

func TestRuntimePackageFeatureCannotBeOmittedBorrowedOrRetargeted(t *testing.T) {
	for name, change := range map[string]func(*Manifest){
		"missing": func(m *Manifest) { m.RequiredPanelFeatures = nil }, "unknown": func(m *Manifest) { m.RequiredPanelFeatures = []string{"unknown"} },
		"duplicate": func(m *Manifest) {
			m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, RuntimePackageVersionFeature)
		}, "extra": func(m *Manifest) { m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, WAFBoundHealthFeature) },
		"foreign-app": func(m *Manifest) { m.ID = "apache" }, "alias-app": func(m *Manifest) { m.ID = "nginx-other" },
		"old-version": func(m *Manifest) { m.Version = "1.30.4-compat1" }, "future-revision": func(m *Manifest) { m.Version = "1.30.6-compat2" }, "future-program": func(m *Manifest) { m.Version = "1.31.5-compat1" },
		"old-target": func(m *Manifest) { m.Delivery.Target = "nginx-1.30.4" }, "provider": func(m *Manifest) { m.Delivery.Provider = "panel-module" }, "route": func(m *Manifest) { m.Delivery.ManageRoute = "runtimes" },
	} {
		t.Run(name, func(t *testing.T) {
			m := runtimePackageManifestFixture()
			change(&m)
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("wrong handler scope accepted")
			}
		})
	}
}

func TestRuntimePackageManifestFullBytesBindActualCompiledHandler(t *testing.T) {
	m := runtimePackageManifestFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/nginx/" + m.Version + "/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	if _, err := client.verifyManifestData(item, raw); (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("actual compiled OS handler ignored", err)
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, err := client.verifyManifestData(item, changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("changed manifest borrowed previous checksum", err)
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	if _, err := client.verifyManifestData(item, changed); err == nil {
		t.Fatal("rehash omitted mandatory compiled runtime handler")
	}
}

func TestRuntimePackageFeatureRetainsHistoricalNginxDeliveryAndClosedOtherProviders(t *testing.T) {
	m := runtimePackageManifestFixture()
	m.Version, m.Delivery.Target, m.RequiredPanelFeatures = "1.30.4-compat1", "nginx-1.30.4", nil
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("historical source scope rewritten", err)
	}
	m = runtimePackageManifestFixture()
	m.ID, m.Version, m.RequiredPanelFeatures = "redis", "8.2.1-compat1", []string{WAFBoundHealthFeature}
	if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
		t.Fatal("runtime delivery borrowed a panel-module feature")
	}
	encoded, _ := json.Marshal(runtimePackageManifestFixture())
	var roundtrip Manifest
	if err := strictJSON(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(roundtrip, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePackageCurrentTargetCannotBorrowHistoricalLabelWithoutHandler(t *testing.T) {
	for _, id := range []string{"nginx", "other-runtime"} {
		m := runtimePackageManifestFixture()
		m.ID, m.Version, m.RequiredPanelFeatures = id, "1.0.0", nil
		if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
			t.Fatal("current fixed native target borrowed an unrelated historical package label without its compiled handler", id)
		}
	}
}
