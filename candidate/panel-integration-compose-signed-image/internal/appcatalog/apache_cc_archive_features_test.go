package appcatalog

import "testing"

func TestApacheCCArchiveManifestCannotBorrowAnOldNativeHandler(t *testing.T) {
	m := apacheNativeBodyManifestFixture()
	m.Version = ApacheCCLogArchiveAppVersion
	m.RequiredPanelFeatures = []string{ApacheNativeBodySiteFeature, ApacheNativeCCSiteFeature, ApacheCCLogArchiveFeature}
	if err := validatePanelRequirements(m, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, missing := range m.RequiredPanelFeatures {
		if validatePanelRequirements(m, func(feature string) bool { return feature != missing }) == nil {
			t.Fatal("partial handler admitted archive authority", missing)
		}
	}
	for _, mutate := range []func(*Manifest){
		func(v *Manifest) { v.Version = "2.5.2" }, func(v *Manifest) { v.Version = "2.5.1-alias" }, func(v *Manifest) { v.Version = "2.5.0" }, func(v *Manifest) { v.ID = "nginx-waf" }, func(v *Manifest) { v.Delivery.Target = "nginx-waf" }, func(v *Manifest) { v.RequiredPanelFeatures = v.RequiredPanelFeatures[:2] }, func(v *Manifest) {
			v.RequiredPanelFeatures[0], v.RequiredPanelFeatures[2] = v.RequiredPanelFeatures[2], v.RequiredPanelFeatures[0]
		},
	} {
		v := m
		v.RequiredPanelFeatures = append([]string{}, m.RequiredPanelFeatures...)
		mutate(&v)
		if validatePanelRequirements(v, func(string) bool { return true }) == nil {
			t.Fatal("unknown archive manifest accepted", v)
		}
	}
	old := apacheNativeBodyManifestFixture()
	old.Version = ApacheNativeCCAppVersion
	old.RequiredPanelFeatures = []string{ApacheNativeBodySiteFeature, ApacheNativeCCSiteFeature}
	if err := validatePanelRequirements(old, func(f string) bool { return f != ApacheCCLogArchiveFeature }); err != nil {
		t.Fatal("original250 manifest changed", err)
	}
}
