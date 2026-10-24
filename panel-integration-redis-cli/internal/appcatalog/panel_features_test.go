package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func panelRequirementFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "website-statistics-v2", Name: "Website statistics-v2", Category: "professional", Version: "2.4.1", Stage: "ready", Risk: "maintained", Summary: "owned handler requirements fixture", Delivery: Delivery{Provider: "panel-module", Target: "website-statistics-v2", ManageRoute: "app-modules"}, Capabilities: []string{"owned bounded history"}, RequiredPanelFeatures: []string{StatisticsCursorRetirementFeature}}
}

func TestGeographyPackageRequiresBoundedReaderNotEarlierPrototype(t *testing.T) {
	m := panelRequirementFixture()
	m.Version = "2.6.0"
	m.RequiredPanelFeatures = []string{StatisticsCursorRetirementFeature, StatisticsRequestIdentityFeature, StatisticsGeographyFeature}
	oldAvailable := func(feature string) bool {
		return feature == StatisticsCursorRetirementFeature || feature == StatisticsRequestIdentityFeature || feature == "statistics-geodata-v1"
	}
	if err := validatePanelRequirements(m, oldAvailable); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("unbounded prototype could authorize bounded2.6 package", err)
	}
	m.RequiredPanelFeatures[2] = "statistics-geodata-v1"
	if validatePanelRequirements(m, oldAvailable) == nil {
		t.Fatal("old geography ABI still claimed final2.6 implementation")
	}
}

func TestPanelRequirementsClosedProviderScopeDuplicatesAndUnsupportedNeverPass(t *testing.T) {
	for _, kind := range []string{"runtime", "compose", "other-app", "other-target", "duplicate", "empty", "traversal", "too-many", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			m := panelRequirementFixture()
			switch kind {
			case "runtime", "compose":
				m.Delivery.Provider = kind
			case "other-app":
				m.ID = "daily-report"
			case "other-target":
				m.Delivery.Target = "daily-report"
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, m.RequiredPanelFeatures[0])
			case "empty":
				m.RequiredPanelFeatures = []string{""}
			case "traversal":
				m.RequiredPanelFeatures = []string{"../handler"}
			case "too-many":
				m.RequiredPanelFeatures = make([]string, 9)
			case "unknown":
				m.RequiredPanelFeatures = []string{"unsupported-handler-v1"}
			}
			if err := validatePanelRequirements(m, func(feature string) bool { return feature == StatisticsCursorRetirementFeature }); err == nil {
				t.Fatal("invalid handler requirement was admitted")
			}
		})
	}
	if err := validatePanelRequirements(panelRequirementFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("unavailable implementation was not refused", err)
	}
	m := panelRequirementFixture()
	m.RequiredPanelFeatures = nil
	m.Version = "2.4.0"
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("existing v1 manifests no longer work", err)
	}
}

func TestPanelRequirementsAreBoundToManifestBytesAndBothVerificationPaths(t *testing.T) {
	m := panelRequirementFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/website-statistics-v2/2.4.1/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	_, err := client.verifyManifestData(item, raw)
	if (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("requirement ignored actual compiled handler availability", err)
	}
	if runtime.GOOS != "linux" && !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("unsupported host refused for the wrong reason", err)
	}
	m.RequiredPanelFeatures = []string{StatisticsCursorRetirementFeature, "unsupported-handler-v1"}
	changed, _ := json.Marshal(m)
	if _, err = client.verifyManifestData(item, changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("unbound requirement bytes accepted", err)
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	if _, err = client.verifyManifestData(item, changed); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("bound unsupported requirement accepted", err)
	}
}

func TestLegacyStrictDecoderRefusesRequiredHandlerFieldInsteadOfIgnoringIt(t *testing.T) {
	// A distinct pre-extension shape proves the existing strict decode
	// contract, rather than calling the new decoder and asserting on itself.
	m := panelRequirementFixture()
	raw, _ := json.Marshal(m)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "required_panel_features")
	legacy, _ := json.Marshal(fields)
	// The only accepted requirement key in the old shape is deliberately
	// absent; all otherwise identical manifest fields remain represented.
	type legacyEnvelope struct {
		SchemaVersion int           `json:"schema_version"`
		ID            string        `json:"id"`
		Name          string        `json:"name"`
		Category      string        `json:"category"`
		Version       string        `json:"version"`
		Summary       string        `json:"summary"`
		Stage         string        `json:"stage"`
		Risk          string        `json:"risk"`
		Delivery      Delivery      `json:"delivery"`
		Compatibility Compatibility `json:"compatibility"`
		Capabilities  []string      `json:"capabilities"`
		Health        Health        `json:"health"`
		Uninstall     Uninstall     `json:"uninstall"`
	}
	var old legacyEnvelope
	if err := strictJSON(legacy, &old); err != nil {
		t.Fatal("legacy fixture is incomplete", err)
	}
	if err := strictJSON(raw, &old); err == nil || !strings.Contains(err.Error(), "required_panel_features") {
		t.Fatal("old panel silently ignored mandatory implementation", err)
	}
}

func TestNewStatisticsVersionsCannotOmitMandatoryHandlerRequirement(t *testing.T) {
	for _, version := range []string{"2.4.1", "2.4.1-compat1", "2.4.2", "2.5.0", "3.0", "18446744073709551616.0"} {
		m := panelRequirementFixture()
		m.Version = version
		for _, requirements := range [][]string{nil, {}, {"unsupported-handler-v1"}} {
			m.RequiredPanelFeatures = requirements
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("new version silently omitted its actual handler", version, requirements)
			}
		}
	}
}

func TestStatisticsIdentityVersionRequiresBothBoundHandlersAndRejectsOldAvailability(t *testing.T) {
	m := panelRequirementFixture()
	m.Version = "2.5.0"
	if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
		t.Fatal("2.5 omitted request identity handler")
	}
	m.RequiredPanelFeatures = []string{StatisticsCursorRetirementFeature, StatisticsRequestIdentityFeature}
	if err := validatePanelRequirements(m, func(f string) bool { return f == StatisticsCursorRetirementFeature }); err == nil {
		t.Fatal("old2.4.1 availability accepted2.5")
	}
	if err := validatePanelRequirements(m, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	m.Delivery.Target = "daily-report"
	if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
		t.Fatal("identity requirement escaped fixed target")
	}
	m.Delivery.Target = m.ID
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/website-statistics-v2/2.5.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	client := &Client{BaseURL: "https://example.invalid"}
	_, err := client.verifyManifestData(item, raw)
	if (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("2.5 did not use actual compiled availability and bound manifest", err)
	}
}
