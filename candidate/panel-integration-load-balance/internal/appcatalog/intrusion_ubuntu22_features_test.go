package appcatalog

import (
	"runtime"
	"testing"
)

func TestIntrusion111RequiresBothExactCompiledHandlers(t *testing.T) {
	fixture := func() Manifest {
		m := intrusionJournalManifestFixture()
		m.Version = "1.1.1"
		m.RequiredPanelFeatures = []string{IntrusionJournalFeature, IntrusionUbuntu22Feature}
		return m
	}
	available := func(f string) bool { return f == IntrusionJournalFeature || f == IntrusionUbuntu22Feature }
	if err := validatePanelRequirements(fixture(), available); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{IntrusionJournalFeature, IntrusionUbuntu22Feature} {
		if err := validatePanelRequirements(fixture(), func(f string) bool { return available(f) && f != missing }); err == nil {
			t.Fatal("old compiled programme accepted111", missing)
		}
	}
	for _, scenario := range []string{"empty", "old-only", "new-only", "duplicate", "extra", "order", "alias", "future", "old-version", "other-app", "target", "route", "provider", "nil-availability"} {
		t.Run(scenario, func(t *testing.T) {
			m, lookup := fixture(), available
			switch scenario {
			case "empty":
				m.RequiredPanelFeatures = nil
			case "old-only":
				m.RequiredPanelFeatures = []string{IntrusionJournalFeature}
			case "new-only":
				m.RequiredPanelFeatures = []string{IntrusionUbuntu22Feature}
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, IntrusionUbuntu22Feature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, HardeningJournalFeature)
			case "order":
				m.RequiredPanelFeatures = []string{IntrusionUbuntu22Feature, IntrusionJournalFeature}
			case "alias":
				m.Version = "1.1.1-compat1"
			case "future":
				m.Version = "1.1.2"
			case "old-version":
				m.Version = "1.1.0"
			case "other-app":
				m.ID = "system-hardening"
			case "target":
				m.Delivery.Target = "system-hardening"
			case "route":
				m.Delivery.ManageRoute = "app-modules"
			case "provider":
				m.Delivery.Provider = "runtime"
			case "nil-availability":
				lookup = nil
			}
			if err := validatePanelRequirements(m, lookup); err == nil {
				t.Fatal("borrowed or incomplete111 authority accepted")
			}
		})
	}
	if IntrusionUbuntu22Feature != "intrusion-upstream0112-v1" || panelFeatureAvailable(IntrusionUbuntu22Feature) != (runtime.GOOS == "linux") || panelFeatureAvailable("intrusion-upstream0112-v2") {
		t.Fatal("wrong platform or future version authorized")
	}
}
