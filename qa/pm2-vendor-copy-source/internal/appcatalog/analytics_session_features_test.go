package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func analyticsSessionManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "website-analytics", Name: "Website Analytics", Category: "professional", Version: "2.3.1", Stage: "ready", Risk: "maintained", Summary: "private source lifecycle fixture", Delivery: Delivery{Provider: "panel-module", Target: "website-analytics", ManageRoute: "app-modules"}, Capabilities: []string{"bounded existing session contract"}, RequiredPanelFeatures: []string{AnalyticsSessionFeature}}
}

func TestAnalyticsSessionManifestRequiresExactCompiledHandlerAndCannotBorrowAuthority(t *testing.T) {
	available := func(feature string) bool { return feature == AnalyticsSessionFeature }
	if err := validatePanelRequirements(analyticsSessionManifestFixture(), available); err != nil {
		t.Fatal("actual handler requirement refused", err)
	}
	if err := validatePanelRequirements(analyticsSessionManifestFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old collector could claim the session fix", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "legacy", "other-app", "target", "route", "runtime", "compose", "wrong-handler"} {
		t.Run(scenario, func(t *testing.T) {
			m := analyticsSessionManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsSessionFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, StatisticsGeographyFeature)
			case "alias":
				m.Version = "2.3.1-compat1"
			case "future":
				m.Version = "2.4.0"
			case "legacy":
				m.Version = "2.3.0"
			case "other-app":
				m.ID, m.Delivery.Target = "daily-report", "daily-report"
			case "target":
				m.Delivery.Target = "website-statistics-v2"
			case "route":
				m.Delivery.ManageRoute = "security"
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

func TestAnalyticsSessionLegacyManifestIsUnchangedAndAvailabilityIsLinuxOnly(t *testing.T) {
	m := analyticsSessionManifestFixture()
	m.Version, m.RequiredPanelFeatures = "2.3.0", nil
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("published2.3.0 lost compatibility", err)
	}
	if panelFeatureAvailable(AnalyticsSessionFeature) != (runtime.GOOS == "linux") {
		t.Fatal("availability did not match compiled supported host")
	}
	if panelFeatureAvailable("analytics-session-lifecycle-v2") {
		t.Fatal("future prototype silently authorized")
	}
}
