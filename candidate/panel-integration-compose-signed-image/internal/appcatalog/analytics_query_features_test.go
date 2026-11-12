package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func analyticsQueryManifestFixture() Manifest {
	m := analyticsRouteManifestFixture()
	m.Version = "2.4.2"
	m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsNavigationOrderFeature, AnalyticsQueryContextFeature)
	return m
}

func TestAnalyticsQueryRequiresExactFiveHandlersAndRetainsOriginalABI(t *testing.T) {
	fixture := analyticsQueryManifestFixture()
	if err := validatePanelRequirements(fixture, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, absent := range fixture.RequiredPanelFeatures {
		if err := validatePanelRequirements(fixture, func(feature string) bool { return feature != absent }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("previous compiled handler accepted a query-only version label", absent, err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "foreign-feature", "previous-version", "future-version", "alias", "build", "leading-zero", "foreign-app", "provider", "target", "route"} {
		t.Run(scenario, func(t *testing.T) {
			m := analyticsQueryManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = m.RequiredPanelFeatures[:4]
			case "duplicate":
				m.RequiredPanelFeatures[0] = AnalyticsQueryContextFeature
			case "foreign-feature":
				m.RequiredPanelFeatures[0] = FilesSyncIndependentBackupFeature
			case "previous-version":
				m.Version = "2.4.1"
			case "future-version":
				m.Version = "2.4.3"
			case "alias":
				m.Version = "2.4.2-compat1"
			case "build":
				m.Version = "2.4.2+build"
			case "leading-zero":
				m.Version = "02.4.2"
			case "foreign-app":
				m.ID, m.Delivery.Target = "daily-report", "daily-report"
			case "provider":
				m.Delivery.Provider = "runtime"
			case "target":
				m.Delivery.Target = "website-statistics-v2"
			case "route":
				m.Delivery.ManageRoute = "security"
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("invalid query ABI admitted", scenario)
			}
		})
	}
	legacy := analyticsRouteManifestFixture()
	legacy.Version = "2.4.1"
	legacy.RequiredPanelFeatures = append(legacy.RequiredPanelFeatures, AnalyticsNavigationOrderFeature)
	if err := validatePanelRequirements(legacy, func(string) bool { return true }); err != nil {
		t.Fatal("previous signed four-handler ABI changed", err)
	}
	if panelFeatureAvailable(AnalyticsQueryContextFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("website-analytics-query-context-v2") {
		t.Fatal("compiled query feature availability is not exact")
	}
}

func TestAnalyticsComparisonAddsItsOwnRequiredFeature(t *testing.T) {
	available := func(string) bool { return true }
	m := analyticsQueryManifestFixture()
	m.Version = "2.4.3"
	if validatePanelRequirements(m, available) == nil {
		t.Fatal("comparison version borrowed the old report handler")
	}
	m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, AnalyticsPeriodComparisonFeature)
	if err := validatePanelRequirements(m, available); err != nil {
		t.Fatal(err)
	}
	if validatePanelRequirements(m, func(feature string) bool { return feature != AnalyticsPeriodComparisonFeature }) == nil {
		t.Fatal("previous panel admitted the new package")
	}
	m.Version = "2.4.2"
	if validatePanelRequirements(m, available) == nil {
		t.Fatal("previous package borrowed the new handler")
	}
}
