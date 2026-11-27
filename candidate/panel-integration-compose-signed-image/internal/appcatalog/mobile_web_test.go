package appcatalog

import (
	"runtime"
	"testing"
)

func TestMobileWeb140NeedsItsOwnCompiledFeature(t *testing.T) {
	m := Manifest{SchemaVersion: 1, ID: "mobile", Version: MobileWebVersion, Delivery: Delivery{Provider: "panel-module", Target: "mobile-pwa", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{MobileWebFeature}}
	if e := validatePanelRequirements(m, func(f string) bool { return f == MobileWebFeature }); e != nil {
		t.Fatal(e)
	}
	if e := validatePanelRequirements(m, func(f string) bool { return f == NativeMobile133Feature }); e == nil {
		t.Fatal("old native handler accepted web140")
	}
	m.RequiredPanelFeatures = []string{NativeMobile133Feature}
	if e := validatePanelRequirements(m, func(string) bool { return true }); e == nil {
		t.Fatal("web140 borrowed native-only requirement")
	}
	if panelFeatureAvailable(MobileWebFeature) != (runtime.GOOS == "linux") {
		t.Fatal("platform capability drift")
	}
}
