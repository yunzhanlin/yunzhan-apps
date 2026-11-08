package appcatalog

import (
	"runtime"
	"testing"
)

func TestEnterpriseKernelRequiresIndependentOwnershipABI(t *testing.T) {
	valid := Manifest{ID: "enterprise-tamper-proof", Version: "1.5.0", Delivery: Delivery{Provider: "panel-module", Target: "enterprise-tamper-proof", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{EnterpriseKernelFeature}}
	yes := func(feature string) bool { return feature == EnterpriseKernelFeature }
	if handled, err := validateEnterpriseKernelRequirement(valid, yes); !handled || err != nil {
		t.Fatal("exact enterprise ABI rejected", handled, err)
	}
	for name, change := range map[string]func(*Manifest){
		"website ABI":                  func(m *Manifest) { m.RequiredPanelFeatures = []string{IntegrityKernelFeature} },
		"website target":               func(m *Manifest) { m.Delivery.Target = "website-tamper-proof" },
		"foreign module":               func(m *Manifest) { m.ID = "file-monitor" },
		"website borrowing enterprise": func(m *Manifest) { m.ID = "website-tamper-proof" },
		"version alias":                func(m *Manifest) { m.Version = "1.5.0-local" },
		"future version":               func(m *Manifest) { m.Version = "1.5.1" },
		"no ABI":                       func(m *Manifest) { m.RequiredPanelFeatures = nil },
		"duplicate ABI": func(m *Manifest) {
			m.RequiredPanelFeatures = []string{EnterpriseKernelFeature, EnterpriseKernelFeature}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := valid
			change(&m)
			if handled, err := validateEnterpriseKernelRequirement(m, yes); !handled || err == nil {
				t.Fatal("unknown/foreign handler admitted enterprise kernel control", handled, err)
			}
		})
	}
	if _, err := validateEnterpriseKernelRequirement(valid, func(string) bool { return false }); err == nil {
		t.Fatal("old panel gained enterprise kernel capability by version label")
	}
	if panelFeatureAvailable(EnterpriseKernelFeature) != (runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")) {
		t.Fatal("enterprise capability claimed on unsupported platform")
	}
}
