package appcatalog

import "testing"

func TestNetworkIDSDurableStopRequiresExactCompiledHandlerAndRetainsOldManifest(t *testing.T) {
	old := Manifest{ID: "network-threat-detection", Version: "1.3.2", Delivery: Delivery{Provider: "panel-module", Target: "network-threat-detection", ManageRoute: "app-modules"}}
	if err := validatePanelRequirements(old, nil); err != nil {
		t.Fatal("original signed manifest no longer accepted", err)
	}
	m := old
	m.Version = NetworkIDSDurableStopVersion
	m.RequiredPanelFeatures = []string{NetworkIDSDurableStopFeature}
	if err := validatePanelRequirements(m, func(feature string) bool { return feature == NetworkIDSDurableStopFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(m, available); err == nil {
			t.Fatal("an old compiled handler authorized the durable-stop update")
		}
	}
	for _, field := range []string{"missing-feature", "duplicate-feature", "foreign-feature", "older-version", "future-version", "compat-version", "target", "provider", "route", "application"} {
		bad := m
		switch field {
		case "missing-feature":
			bad.RequiredPanelFeatures = nil
		case "duplicate-feature":
			bad.RequiredPanelFeatures = []string{NetworkIDSDurableStopFeature, NetworkIDSDurableStopFeature}
		case "foreign-feature":
			bad.RequiredPanelFeatures = []string{NetworkIDSDurableStopFeature, "unrelated-handler"}
		case "older-version":
			bad.Version = old.Version
		case "future-version":
			bad.Version = "1.3.4"
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
			t.Fatal("incorrect durable-stop manifest accepted", field)
		}
	}
}
