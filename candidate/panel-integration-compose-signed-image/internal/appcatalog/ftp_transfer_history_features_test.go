package appcatalog

import "testing"

func TestFTPTransferHistoryRequiresItsExactPackageAndFeature(t *testing.T) {
	valid := Manifest{ID: "pure-ftpd", Version: FTPTransferHistoryVersion,
		Delivery:              Delivery{Provider: "panel-module", Target: "pure-ftpd", ManageRoute: "app-modules"},
		RequiredPanelFeatures: []string{FTPTransferHistoryFeature}}
	available := func(feature string) bool { return feature == FTPTransferHistoryFeature }
	if ok, err := validateFTPTransferHistoryRequirement(valid, available); !ok || err != nil {
		t.Fatalf("valid package rejected: %v", err)
	}
	if ok, err := validateFTPTransferHistoryRequirement(valid, nil); !ok || err == nil {
		t.Fatal("package admitted without a compiled handler")
	}
	for _, edit := range []func(*Manifest){
		func(m *Manifest) { m.Version = "1.0.54-compat07" },
		func(m *Manifest) { m.Version = "1.0.54-compat8"; m.RequiredPanelFeatures = nil },
		func(m *Manifest) { m.RequiredPanelFeatures = nil },
		func(m *Manifest) { m.ID = "nfs-manager" },
		func(m *Manifest) { m.Delivery.Target = "daily-report" },
		func(m *Manifest) { m.Delivery.ManageRoute = "files" },
	} {
		m := valid
		edit(&m)
		if ok, err := validateFTPTransferHistoryRequirement(m, available); !ok || err == nil {
			t.Fatalf("unbound feature accepted: %+v", m)
		}
	}
	legacy := valid
	legacy.Version, legacy.RequiredPanelFeatures = "1.0.54-compat6", nil
	if ok, err := validateFTPTransferHistoryRequirement(legacy, available); ok || err != nil {
		t.Fatalf("legacy manifest behavior changed: %v", err)
	}
}
