package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func analyticsRouteManifestFixture() Manifest {
	m := analyticsClientManifestFixture()
	m.Version = "2.4.0"
	m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsRoutePerformanceFeature)
	return m
}

func TestAnalyticsRouteManifestRequiresAllHandlersAndExactApp(t *testing.T) {
	if err := validatePanelRequirements(analyticsRouteManifestFixture(), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{AnalyticsSessionFeature, AnalyticsClientAddressFeature, AnalyticsRoutePerformanceFeature, "all"} {
		if err := validatePanelRequirements(analyticsRouteManifestFixture(), func(f string) bool { return absent != "all" && f != absent }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("old binary claimed route capability", absent, err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "old", "future", "alias", "build", "leading-zero", "other-app", "target", "route", "runtime"} {
		t.Run(scenario, func(t *testing.T) {
			m := analyticsRouteManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = m.RequiredPanelFeatures[:2]
			case "duplicate":
				m.RequiredPanelFeatures[0] = AnalyticsRoutePerformanceFeature
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, StatisticsGeographyFeature)
			case "old":
				m.Version = "2.3.2"
			case "future":
				m.Version = "2.4.1"
			case "alias":
				m.Version = "2.4.0-compat1"
			case "build":
				m.Version = "2.4.0+build"
			case "leading-zero":
				m.Version = "02.4.0"
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
				t.Fatal("invalid route handler claim", scenario)
			}
		})
	}
	if panelFeatureAvailable(AnalyticsRoutePerformanceFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("analytics-route-readiness-v2") {
		t.Fatal("compiled handler availability")
	}
}
