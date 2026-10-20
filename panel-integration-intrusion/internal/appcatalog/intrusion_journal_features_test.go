package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func intrusionJournalManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "anti-intrusion", Name: "SSH 防入侵", Category: "professional", Version: "1.1.0", Stage: "ready", Risk: "maintained", Summary: "private manifest contract fixture, not installed acceptance", Delivery: Delivery{Provider: "panel-module", Target: "intrusion-prevention", ManageRoute: "security"}, RequiredPanelFeatures: []string{IntrusionJournalFeature}}
}

func TestIntrusionJournalManifestRequiresActualFixedLinuxHandler(t *testing.T) {
	if err := validatePanelRequirements(intrusionJournalManifestFixture(), func(f string) bool { return f == IntrusionJournalFeature }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(intrusionJournalManifestFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old handler silently adopted feature", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "legacy-feature", "other-app", "target", "executor-name-as-app", "route", "runtime", "compose", "wrong-handler"} {
		t.Run(scenario, func(t *testing.T) {
			m := intrusionJournalManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, IntrusionJournalFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, HardeningJournalFeature)
			case "alias":
				m.Version = "1.1.0-alias"
			case "future":
				m.Version = "1.2.0"
			case "legacy-feature":
				m.Version = "1.0"
			case "other-app":
				m.ID = "system-hardening"
			case "executor-name-as-app":
				m.ID = "intrusion-prevention"
			case "target":
				m.Delivery.Target = "system-hardening"
			case "route":
				m.Delivery.ManageRoute = "app-modules"
			case "runtime", "compose":
				m.Delivery.Provider = scenario
			case "wrong-handler":
				m.RequiredPanelFeatures = []string{HardeningJournalFeature}
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("borrowed manifest authority", scenario)
			}
		})
	}
}

func TestIntrusionJournalKeepsLegacyManifestAndRejectsFutureAvailability(t *testing.T) {
	m := intrusionJournalManifestFixture()
	m.Version = "1.0"
	m.RequiredPanelFeatures = nil
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("old signed manifest changed", err)
	}
	if panelFeatureAvailable(IntrusionJournalFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("intrusion-preserving-journal-v2") {
		t.Fatal("uncompiled platform or prototype authorized")
	}
}
