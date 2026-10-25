package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func mobileDeliveryFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "mobile", Version: NativeMobileVersion, Delivery: Delivery{Provider: "panel-module", Target: "mobile-pwa", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{NativeMobileDeliveryFeature}}
}

func TestNativeMobileDeliveryRequiresExactCompiledHandler(t *testing.T) {
	if err := validatePanelRequirements(mobileDeliveryFixture(), func(f string) bool { return f == NativeMobileDeliveryFeature }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(mobileDeliveryFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old handler could advertise new client delivery", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "unpublished131", "legacy-with-feature", "foreign-id", "foreign-id-without-feature", "target", "route", "runtime", "compose", "wrong-feature"} {
		t.Run(scenario, func(t *testing.T) {
			m := mobileDeliveryFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, NativeMobileDeliveryFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsSessionFeature)
			case "alias":
				m.Version = "1.3.2-compat1"
			case "future":
				m.Version = "1.4.0"
			case "unpublished131":
				m.Version, m.RequiredPanelFeatures = "1.3.1", nil
			case "legacy-with-feature":
				m.Version = "1.3.0"
			case "foreign-id":
				m.ID = "daily-report"
			case "foreign-id-without-feature":
				m.ID, m.RequiredPanelFeatures = "daily-report", nil
			case "target":
				m.Delivery.Target = "website-analytics"
			case "route":
				m.Delivery.ManageRoute = "security"
			case "runtime", "compose":
				m.Delivery.Provider = scenario
			case "wrong-feature":
				m.RequiredPanelFeatures = []string{AnalyticsSessionFeature}
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("borrowed fixed mobile delivery", scenario)
			}
		})
	}
}

func TestNativeMobileLegacyManifestsAndPlatformBoundary(t *testing.T) {
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0"} {
		m := mobileDeliveryFixture()
		m.Version, m.RequiredPanelFeatures = version, nil
		if err := validatePanelRequirements(m, nil); err != nil {
			t.Fatal("historical manifest lost acceptance", version, err)
		}
	}
	for _, version := range []string{"1.0.0", "1.0-compat2", "1.2.1", "01.3.0", "1.3.1", "1.3.2-compat1", "1.3.3", "18446744073709551616.0.0", "unknown"} {
		m := mobileDeliveryFixture()
		m.Version, m.RequiredPanelFeatures = version, nil
		if NativeMobileUpdateVersionAllowed(version) {
			t.Fatal("unpublished native client identity accepted", version)
		}
		if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
			t.Fatal("unpublished client bypassed the exact mobile handler", version)
		}
	}
	if panelFeatureAvailable(NativeMobileDeliveryFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("mobile-native-delivery-v133") {
		t.Fatal("native mobile feature platform or revision scope widened")
	}
}
