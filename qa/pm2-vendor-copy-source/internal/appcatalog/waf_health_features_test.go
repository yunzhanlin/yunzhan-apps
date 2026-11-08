package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func wafHealthManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "nginx-waf", Name: "Nginx 请求防火墙", Category: "professional", Version: "2.5.2", Stage: "ready", Risk: "maintained", Summary: "site-bound health handler fixture, not installed acceptance", Delivery: Delivery{Provider: "panel-module", Target: "nginx-waf", ManageRoute: "security"}, RequiredPanelFeatures: []string{WAFBoundHealthFeature}}
}

func TestWAFHealthManifestRequiresActualVersionBoundLinuxHandler(t *testing.T) {
	if err := validatePanelRequirements(wafHealthManifestFixture(), func(f string) bool { return f == WAFBoundHealthFeature }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(wafHealthManifestFixture(), func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old panel adopted unsupported handler", err)
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "old", "other-app", "target", "route", "runtime", "compose", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			m := wafHealthManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, WAFBoundHealthFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, IntrusionJournalFeature)
			case "alias":
				m.Version = "2.5.2-alias"
			case "future":
				m.Version = "2.6.0"
			case "old":
				m.Version = "2.5.1"
			case "other-app":
				m.ID = "apache-waf"
			case "target":
				m.Delivery.Target = "apache-waf"
			case "route":
				m.Delivery.ManageRoute = "app-modules"
			case "runtime", "compose":
				m.Delivery.Provider = scenario
			case "unknown":
				m.RequiredPanelFeatures = []string{"waf-bound-health-v2"}
			}
			if validatePanelRequirements(m, func(string) bool { return true }) == nil {
				t.Fatal("borrowed health handler", scenario)
			}
		})
	}
	for _, version := range []string{"2.0.1", "2.4.0", "2.5.0", "2.5.1"} {
		m := wafHealthManifestFixture()
		m.Version = version
		m.RequiredPanelFeatures = nil
		if err := validatePanelRequirements(m, nil); err != nil {
			t.Fatal("original manifest rejected", version, err)
		}
	}
	if panelFeatureAvailable(WAFBoundHealthFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("waf-bound-health-v2") {
		t.Fatal("uncompiled platform/future handler authorized")
	}
}
