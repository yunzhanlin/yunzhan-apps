package appcatalog

import (
	"runtime"
	"strings"
	"testing"
)

func TestPHPSecurityCompiledHandlerExactFourBranchBindings(t *testing.T) {
	for _, id := range []string{"php-82", "php-83", "php-84", "php-85"} {
		v, _ := phpSecurityBinding(id)
		valid := Manifest{ID: id, Version: v + "-compat1", Delivery: Delivery{Provider: "runtime", Target: "php-" + v, ManageRoute: "runtimes"}, RequiredPanelFeatures: []string{PHPSecurity20261021Feature}}
		if e := validatePanelRequirements(valid, func(f string) bool { return f == PHPSecurity20261021Feature }); e != nil {
			t.Fatal(id, e)
		}
		if e := validatePanelRequirements(valid, func(string) bool { return false }); e == nil || !strings.Contains(e.Error(), "请先升级面板") {
			t.Fatal("missing compiled capability accepted", id, e)
		}
		for _, scenario := range []string{"missing", "duplicate", "extra", "old-label", "unreviewed-version", "foreign-id", "foreign-id-without-feature", "branch", "provider", "route", "wrong-feature", "wrong-target"} {
			t.Run(id+"/"+scenario, func(t *testing.T) {
				m := valid
				m.RequiredPanelFeatures = append([]string{}, valid.RequiredPanelFeatures...)
				switch scenario {
				case "missing":
					m.RequiredPanelFeatures = nil
				case "duplicate":
					m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, PHPSecurity20261021Feature)
				case "extra":
					m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, NativeMobileDeliveryFeature)
				case "old-label":
					m.Version = "8.2.33-compat1"
				case "unreviewed-version":
					m.Version = v + "-compat2"
				case "foreign-id":
					m.ID = "daily-report"
				case "foreign-id-without-feature":
					m.ID = "daily-report"
					m.RequiredPanelFeatures = nil
				case "branch":
					m.ID = "php-81"
				case "provider":
					m.Delivery.Provider = "panel-module"
				case "route":
					m.Delivery.ManageRoute = "sites"
				case "wrong-feature":
					m.RequiredPanelFeatures = []string{RuntimePackageVersionFeature}
				case "wrong-target":
					m.Delivery.Target = "php-8.2.33"
				}
				if e := validatePanelRequirements(m, func(string) bool { return true }); e == nil {
					t.Fatal("borrowed patch capability", scenario)
				}
			})
		}
	}
	if panelFeatureAvailable(PHPSecurity20261021Feature) != (runtime.GOOS == "linux") || panelFeatureAvailable("php-security-20261021-v2") {
		t.Fatal("platform or revision authority widened")
	}
}
func TestPHPSecurityHistoricalPackagesStillDecodeWithoutClaimingNewPatch(t *testing.T) {
	for _, old := range []struct{ id, version string }{{"php-82", "8.2.33"}, {"php-83", "8.3.33"}, {"php-84", "8.4.25"}, {"php-85", "8.5.10"}} {
		for _, suffix := range []string{"", "-compat1"} {
			m := Manifest{ID: old.id, Version: old.version + suffix, Delivery: Delivery{Provider: "runtime", Target: "php-" + old.version, ManageRoute: "runtimes"}}
			if e := validatePanelRequirements(m, nil); e != nil {
				t.Fatal(old, suffix, e)
			}
		}
	}
}
