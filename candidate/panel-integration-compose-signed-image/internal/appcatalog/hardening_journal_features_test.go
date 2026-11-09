package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func hardeningJournalManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "system-hardening", Name: "System hardening", Category: "professional", Version: "1.1.0", Stage: "ready", Risk: "maintained", Summary: "private source lifecycle fixture", Delivery: Delivery{Provider: "panel-module", Target: "system-hardening", ManageRoute: "security"}, Capabilities: []string{"bounded existing session contract"}, RequiredPanelFeatures: []string{HardeningJournalFeature}}
}

func TestHardeningJournalManifestRequiresExactCompiledHandlerAndCannotBorrowAuthority(t *testing.T) {
	available := func(feature string) bool { return feature == HardeningJournalFeature }
	if err := validatePanelRequirements(hardeningJournalManifestFixture(), available); err != nil {
		t.Fatal("actual handler requirement refused", err)
	}
	if err := validatePanelRequirements(hardeningJournalManifestFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old collector could claim the session fix", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "legacy", "other-app", "target", "route", "runtime", "compose", "wrong-handler"} {
		t.Run(scenario, func(t *testing.T) {
			m := hardeningJournalManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, HardeningJournalFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, StatisticsGeographyFeature)
			case "alias":
				m.Version = "1.1.0-compat1"
			case "future":
				m.Version = "1.2.0"
			case "legacy":
				m.Version = "1.0-compat1"
			case "other-app":
				m.ID, m.Delivery.Target = "daily-report", "daily-report"
			case "target":
				m.Delivery.Target = "website-statistics-v2"
			case "route":
				m.Delivery.ManageRoute = "app-modules"
			case "runtime", "compose":
				m.Delivery.Provider = scenario
			case "wrong-handler":
				m.RequiredPanelFeatures = []string{StatisticsGeographyFeature}
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("manifest could borrow fixed session authority", scenario)
			}
		})
	}
}

func TestHardeningJournalLegacyManifestIsUnchangedAndAvailabilityIsLinuxOnly(t *testing.T) {
	m := hardeningJournalManifestFixture()
	m.Version, m.RequiredPanelFeatures = "1.0-compat1", nil
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("published1.0-compat1 lost compatibility", err)
	}
	if panelFeatureAvailable(HardeningJournalFeature) != (runtime.GOOS == "linux") {
		t.Fatal("availability did not match compiled supported host")
	}
	if panelFeatureAvailable("hardening-reversible-journal-v2") {
		t.Fatal("future prototype silently authorized")
	}
}
