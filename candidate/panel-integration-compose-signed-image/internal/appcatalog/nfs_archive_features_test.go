package appcatalog

import "testing"

func TestNFSSiteArchivePreflightRequiresExactCompiledHandlerAndRetainsOldManifest(t *testing.T) {
	old := Manifest{ID: "nfs-manager", Version: "1.3.1", Delivery: Delivery{Provider: "panel-module", Target: "nfs-manager", ManageRoute: "app-modules"}}
	if err := validatePanelRequirements(old, func(string) bool { return false }); err != nil {
		t.Fatal("original signed manifest no longer accepted", err)
	}
	m := old
	m.Version = NFSSiteArchivePreflightVersion
	m.RequiredPanelFeatures = []string{NFSSiteArchivePreflightFeature}
	if err := validatePanelRequirements(m, func(feature string) bool { return feature == NFSSiteArchivePreflightFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(m, available); err == nil {
			t.Fatal("an old compiled handler authorized the NFS archive-preflight update")
		}
	}
	for _, field := range []string{"missing-feature", "duplicate-feature", "foreign-feature", "older-version", "future-version", "compat-version", "target", "provider", "route", "application"} {
		bad := m
		switch field {
		case "missing-feature":
			bad.RequiredPanelFeatures = nil
		case "duplicate-feature":
			bad.RequiredPanelFeatures = []string{NFSSiteArchivePreflightFeature, NFSSiteArchivePreflightFeature}
		case "foreign-feature":
			bad.RequiredPanelFeatures = []string{NFSSiteArchivePreflightFeature, "unrelated-handler"}
		case "older-version":
			bad.Version = old.Version
		case "future-version":
			bad.Version = "1.3.3"
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
			t.Fatal("incorrect NFS archive-preflight manifest accepted", field)
		}
	}
}
