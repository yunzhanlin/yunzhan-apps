package appcatalog

import (
	"runtime"
	"testing"
)

func TestIntegrityKernelManifestCannotBorrowVersionOrPrivilege(t *testing.T) {
	fixture := func() Manifest {
		return Manifest{ID: "website-tamper-proof", Version: "1.5.0", Delivery: Delivery{Provider: "panel-module", Target: "website-tamper-proof", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{IntegrityKernelFeature}}
	}
	if err := validatePanelRequirements(fixture(), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if validatePanelRequirements(fixture(), func(string) bool { return false }) == nil {
		t.Fatal("old handler acquired new inode authority")
	}
	for _, scenario := range []string{"missing", "duplicate", "foreign-feature", "previous", "future", "alias", "build", "leading-zero", "foreign-app", "wrong-provider", "wrong-target", "wrong-route"} {
		t.Run(scenario, func(t *testing.T) {
			m := fixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, IntegrityKernelFeature)
			case "foreign-feature":
				m.RequiredPanelFeatures = []string{HardeningJournalFeature}
			case "previous":
				m.Version = "1.4.1"
			case "future":
				m.Version = "1.5.1"
			case "alias":
				m.Version = "1.5.0-compat1"
			case "build":
				m.Version = "1.5.0+build"
			case "leading-zero":
				m.Version = "01.5.0"
			case "foreign-app":
				m.ID = "enterprise-tamper-proof"
				m.Delivery.Target = m.ID
			case "wrong-provider":
				m.Delivery.Provider = "runtime"
			case "wrong-target":
				m.Delivery.Target = "file-monitor"
			case "wrong-route":
				m.Delivery.ManageRoute = "security"
			}
			if validatePanelRequirements(m, func(string) bool { return true }) == nil {
				t.Fatal("invalid kernel manifest accepted")
			}
		})
	}
	legacy := fixture()
	legacy.Version = "1.4.1"
	legacy.RequiredPanelFeatures = nil
	if err := validatePanelRequirements(legacy, func(string) bool { return true }); err != nil {
		t.Fatal("original monitor-only manifest changed", err)
	}
	if panelFeatureAvailable(IntegrityKernelFeature) != (runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")) || panelFeatureAvailable("integrity-kernel-inode-journal-v2") {
		t.Fatal("kernel feature availability")
	}
}
