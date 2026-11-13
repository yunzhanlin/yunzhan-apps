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

func TestIntrusion112RequiresExactPlatformAndThreeCompiledHandlers(t *testing.T) {
	fixture := func() Manifest {
		m := intrusionJournalManifestFixture()
		m.Version = IntrusionDebian12Version
		m.RequiredPanelFeatures = []string{IntrusionJournalFeature, IntrusionUbuntu22Feature, IntrusionDebian12Feature}
		m.Compatibility.OS = []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04"}
		m.Compatibility.Architectures = []string{"amd64", "arm64"}
		return m
	}
	available := func(f string) bool {
		return f == IntrusionJournalFeature || f == IntrusionUbuntu22Feature || f == IntrusionDebian12Feature
	}
	if err := validatePanelRequirements(fixture(), available); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Manifest){
		"missing-feature": func(m *Manifest) { m.RequiredPanelFeatures = m.RequiredPanelFeatures[:2] },
		"unknown-release": func(m *Manifest) { m.Version = "1.1.3" },
		"former-release":  func(m *Manifest) { m.Version = "1.1.1" },
		"missing-debian":  func(m *Manifest) { m.Compatibility.OS = m.Compatibility.OS[1:] },
		"extra-os":        func(m *Manifest) { m.Compatibility.OS = append(m.Compatibility.OS, "ubuntu-26.04") },
		"unknown-arch":    func(m *Manifest) { m.Compatibility.Architectures[0] = "386" },
	} {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			change(&m)
			if err := validatePanelRequirements(m, available); err == nil {
				t.Fatal("incompatible manifest accepted")
			}
		})
	}
	if err := validatePanelRequirements(fixture(), func(f string) bool {
		return available(f) && f != IntrusionDebian12Feature
	}); err == nil {
		t.Fatal("former programme accepted 1.1.2")
	}
}
