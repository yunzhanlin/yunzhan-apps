package appcatalog

import "testing"

func TestNetworkIDSIndependentArchiveRequiresExactCompiledHandlerAndRetainsOldManifest(t *testing.T) {
	old := Manifest{ID: "network-threat-detection", Version: "1.3.3", RequiredPanelFeatures: []string{NetworkIDSDurableStopFeature}, Delivery: Delivery{Provider: "panel-module", Target: "network-threat-detection", ManageRoute: "app-modules"}}
	if err := validatePanelRequirements(old, func(f string) bool { return f == NetworkIDSDurableStopFeature }); err != nil {
		t.Fatal("original signed manifest no longer accepted", err)
	}
	m := old
	m.Version = NetworkIDSIndependentArchiveVersion
	m.RequiredPanelFeatures = []string{NetworkIDSIndependentArchiveFeature}
	if err := validatePanelRequirements(m, func(feature string) bool { return feature == NetworkIDSIndependentArchiveFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(m, available); err == nil {
			t.Fatal("an old compiled handler authorized the independent-archive update")
		}
	}
	for _, field := range []string{"missing-feature", "duplicate-feature", "foreign-feature", "older-version", "future-version", "compat-version", "target", "provider", "route", "application"} {
		bad := m
		switch field {
		case "missing-feature":
			bad.RequiredPanelFeatures = nil
		case "duplicate-feature":
			bad.RequiredPanelFeatures = []string{NetworkIDSIndependentArchiveFeature, NetworkIDSIndependentArchiveFeature}
		case "foreign-feature":
			bad.RequiredPanelFeatures = []string{NetworkIDSIndependentArchiveFeature, "unrelated-handler"}
		case "older-version":
			bad.Version = old.Version
		case "future-version":
			bad.Version = "1.3.5"
		case "compat-version":
			bad.Version += "-compat1"
		case "target":
			bad.Delivery.Target = "file-monitor"
		case "provider":
			bad.Delivery.Provider = "runtime"
		case "route":
			bad.Delivery.ManageRoute = "software"
		case "application":
			bad.ID = "file-monitor"
		}
		if err := validatePanelRequirements(bad, func(string) bool { return true }); err == nil {
			t.Fatal("incorrect independent-archive manifest accepted", field)
		}
	}
}
