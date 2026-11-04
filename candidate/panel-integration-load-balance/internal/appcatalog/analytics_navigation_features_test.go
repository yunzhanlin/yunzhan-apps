package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func TestAnalyticsNavigationManifestRequiresFourExactScopedHandlers(t *testing.T) {
	fixture := func() Manifest {
		m := analyticsRouteManifestFixture()
		m.Version = "2.4.1"
		m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsNavigationOrderFeature)
		return m
	}
	if err := validatePanelRequirements(fixture(), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{AnalyticsSessionFeature, AnalyticsClientAddressFeature, AnalyticsRoutePerformanceFeature, AnalyticsNavigationOrderFeature} {
		if err := validatePanelRequirements(fixture(), func(f string) bool { return f != absent }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("previous binary claimed a new ordering contract", absent, err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "foreign-feature", "previous-version", "future", "alias", "build", "leading-zero", "foreign-app", "wrong-provider", "wrong-target", "wrong-route"} {
		t.Run(scenario, func(t *testing.T) {
			m := fixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = m.RequiredPanelFeatures[:3]
			case "duplicate":
				m.RequiredPanelFeatures[0] = AnalyticsNavigationOrderFeature
			case "foreign-feature":
				m.RequiredPanelFeatures[0] = StatisticsGeographyFeature
			case "previous-version":
				m.Version = "2.4.0"
			case "future":
				m.Version = "2.4.2"
			case "alias":
				m.Version = "2.4.1-compat1"
			case "build":
				m.Version = "2.4.1+build"
			case "leading-zero":
				m.Version = "02.4.1"
			case "foreign-app":
				m.ID, m.Delivery.Target = "daily-report", "daily-report"
			case "wrong-provider":
				m.Delivery.Provider = "runtime"
			case "wrong-target":
				m.Delivery.Target = "website-statistics-v2"
			case "wrong-route":
				m.Delivery.ManageRoute = "security"
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("invalid navigation ABI accepted", scenario)
			}
		})
	}
	if panelFeatureAvailable(AnalyticsNavigationOrderFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("analytics-navigation-order-v2") {
		t.Fatal("compiled ordering handler availability")
	}
	// Previously signed route manifests keep their original three-handler ABI.
	if err := validatePanelRequirements(analyticsRouteManifestFixture(), func(string) bool { return true }); err != nil {
		t.Fatal("original 2.4.0 contract changed", err)
	}
}
