package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func analyticsClientManifestFixture() Manifest {
	m := analyticsSessionManifestFixture()
	m.Version = "2.3.2"
	m.RequiredPanelFeatures = []string{AnalyticsSessionFeature, AnalyticsClientAddressFeature}
	return m
}

func TestAnalyticsClientAddressManifestRequiresBothHandlersAndExactIdentity(t *testing.T) {
	available := func(feature string) bool {
		return feature == AnalyticsSessionFeature || feature == AnalyticsClientAddressFeature
	}
	if err := validatePanelRequirements(analyticsClientManifestFixture(), available); err != nil {
		t.Fatal(err)
	}
	for _, present := range []string{"none", AnalyticsSessionFeature, AnalyticsClientAddressFeature} {
		if err := validatePanelRequirements(analyticsClientManifestFixture(), func(f string) bool { return f == present }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("An older collector borrowed the protected-ingress capability", present, err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "session-only", "address-only", "future", "legacy", "alias", "build-alias", "other-app", "target", "route", "runtime"} {
		t.Run(scenario, func(t *testing.T) {
			m := analyticsClientManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = []string{AnalyticsClientAddressFeature, AnalyticsClientAddressFeature}
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, StatisticsGeographyFeature)
			case "session-only":
				m.RequiredPanelFeatures = []string{AnalyticsSessionFeature}
			case "address-only":
				m.RequiredPanelFeatures = []string{AnalyticsClientAddressFeature}
			case "future":
				m.Version = "2.3.3"
			case "legacy":
				m.Version = "2.3.1"
			case "alias":
				m.Version = "2.3.2-compat1"
			case "build-alias":
				m.Version = "2.3.2+build"
			case "other-app":
				m.ID, m.Delivery.Target = "daily-report", "daily-report"
			case "target":
				m.Delivery.Target = "website-statistics-v2"
			case "route":
				m.Delivery.ManageRoute = "security"
			case "runtime":
				m.Delivery.Provider = "runtime"
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("Unreviewed application borrowed a protected ingress handler", scenario)
			}
		})
	}
	if panelFeatureAvailable(AnalyticsClientAddressFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("analytics-managed-client-address-v2") {
		t.Fatal("Availability does not match the compiled Linux handler")
	}
}
