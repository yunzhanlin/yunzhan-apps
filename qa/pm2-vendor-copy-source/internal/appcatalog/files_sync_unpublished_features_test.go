package appcatalog

import "testing"

func TestFilesSyncUnpublishedRetentionRequiresBothExactCompiledHandlers(t *testing.T) {
	m := Manifest{ID: "files-sync", Version: FilesSyncUnpublishedRetentionVersion, Delivery: Delivery{Provider: "panel-module", Target: "files-sync", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{FilesSyncIndependentBackupFeature, FilesSyncUnpublishedRetentionFeature}}
	available := func(f string) bool {
		return f == FilesSyncIndependentBackupFeature || f == FilesSyncUnpublishedRetentionFeature
	}
	if err := validatePanelRequirements(m, available); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Manifest){
		"old copy ABI only": func(v *Manifest) { v.RequiredPanelFeatures = []string{FilesSyncIndependentBackupFeature} },
		"new handler only":  func(v *Manifest) { v.RequiredPanelFeatures = []string{FilesSyncUnpublishedRetentionFeature} },
		"no handler":        func(v *Manifest) { v.RequiredPanelFeatures = nil },
		"duplicate handler": func(v *Manifest) {
			v.RequiredPanelFeatures = []string{FilesSyncUnpublishedRetentionFeature, FilesSyncUnpublishedRetentionFeature}
		},
		"borrowed handler": func(v *Manifest) {
			v.RequiredPanelFeatures = []string{FilesSyncUnpublishedRetentionFeature, AnalyticsQueryContextFeature}
		},
		"unknown version":   func(v *Manifest) { v.Version = "2.0.2" },
		"alias":             func(v *Manifest) { v.Version += "-compat1" },
		"old label":         func(v *Manifest) { v.Version = FilesSyncIndependentBackupVersion },
		"other application": func(v *Manifest) { v.ID = "website-tamper-proof" },
		"other target":      func(v *Manifest) { v.Delivery.Target = "website-tamper-proof" },
		"other provider":    func(v *Manifest) { v.Delivery.Provider = "system-package" },
		"other route":       func(v *Manifest) { v.Delivery.ManageRoute = "software" },
	} {
		t.Run(name, func(t *testing.T) {
			v := m
			change(&v)
			if validatePanelRequirements(v, available) == nil {
				t.Fatal("unbound unpublished-retention capability accepted")
			}
		})
	}
	for _, missing := range []string{FilesSyncIndependentBackupFeature, FilesSyncUnpublishedRetentionFeature} {
		if validatePanelRequirements(m, func(f string) bool { return available(f) && f != missing }) == nil {
			t.Fatal("missing compiled capability accepted", missing)
		}
	}
	for _, version := range []string{"1.9.0", FilesSyncIndependentBackupVersion} {
		v := m
		v.Version, v.RequiredPanelFeatures = version, nil
		if version == FilesSyncIndependentBackupVersion {
			v.RequiredPanelFeatures = []string{FilesSyncIndependentBackupFeature}
		}
		if err := validatePanelRequirements(v, available); err != nil {
			t.Fatal("original signed version changed", version, err)
		}
	}
}
