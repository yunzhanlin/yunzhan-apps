package appcatalog

import "testing"

func TestFilesSyncIndependentBackupRequiresItsExactCompiledABI(t *testing.T) {
	m := Manifest{ID: "files-sync", Version: FilesSyncIndependentBackupVersion, Delivery: Delivery{Provider: "panel-module", Target: "files-sync", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{FilesSyncIndependentBackupFeature}}
	available := func(feature string) bool { return feature == FilesSyncIndependentBackupFeature }
	if handled, err := validateFilesSyncCopyRequirement(m, available); !handled || err != nil {
		t.Fatal(handled, err)
	}
	for name, change := range map[string]func(*Manifest){
		"old label":         func(m *Manifest) { m.Version = "1.9.0" },
		"version alias":     func(m *Manifest) { m.Version += "-compat1" },
		"future version":    func(m *Manifest) { m.Version = "2.0.1" },
		"other application": func(m *Manifest) { m.ID = "website-tamper-proof" },
		"other target":      func(m *Manifest) { m.Delivery.Target = "website-tamper-proof" },
		"other route":       func(m *Manifest) { m.Delivery.ManageRoute = "software" },
		"missing ABI":       func(m *Manifest) { m.RequiredPanelFeatures = nil },
		"borrowed ABI":      func(m *Manifest) { m.RequiredPanelFeatures = []string{IntegrityKernelFeature} },
		"duplicate ABI": func(m *Manifest) {
			m.RequiredPanelFeatures = []string{FilesSyncIndependentBackupFeature, FilesSyncIndependentBackupFeature}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := m
			change(&v)
			if handled, err := validateFilesSyncCopyRequirement(v, available); !handled || err == nil {
				t.Fatal("unbound independent backup capability accepted", handled, err)
			}
		})
	}
	if _, err := validateFilesSyncCopyRequirement(m, func(string) bool { return false }); err == nil {
		t.Fatal("old compiled handler gained independent backup capability")
	}
	legacy := m
	legacy.Version, legacy.RequiredPanelFeatures = "1.9.0", nil
	if handled, err := validateFilesSyncCopyRequirement(legacy, available); handled || err != nil {
		t.Fatal("previous signed SFTP archive ABI changed", handled, err)
	}
}
