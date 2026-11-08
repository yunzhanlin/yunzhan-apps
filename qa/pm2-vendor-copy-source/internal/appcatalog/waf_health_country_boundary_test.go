package appcatalog

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestWAFHealthPatchCannotActivateOrBorrowSeparateCountryHandler(t *testing.T) {
	health := wafHealthManifestFixture()
	if err := validatePanelRequirements(health, func(f string) bool { return f == WAFBoundHealthFeature }); err != nil {
		t.Fatal(err)
	}
	_, in, _, _ := countryChannelFixture(t)
	var country Manifest
	if json.Unmarshal(in.AppManifest, &country) != nil {
		t.Fatal("explicit synthetic country fixture")
	}
	if CountryDataSupported() != (runtime.GOOS == "linux") || (validatePanelRequirements(country, panelFeatureAvailable) == nil) != (runtime.GOOS == "linux") {
		t.Fatal("country ABI availability differs from the compiled platform")
	}
	if err := validatePanelRequirements(country, func(f string) bool { return f == CountryDataFeature }); err != nil {
		t.Fatal("separate explicit synthetic future ABI was erased", err)
	}
	for _, m := range []Manifest{health, country} {
		m.RequiredPanelFeatures = []string{WAFBoundHealthFeature, CountryDataFeature}
		if validatePanelRequirements(m, func(string) bool { return true }) == nil {
			t.Fatal("mixed handlers accepted by a version label")
		}
	}
}
