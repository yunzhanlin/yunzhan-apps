package appcatalog

import (
	"runtime"
	"testing"
)

func TestApacheCCManifestRequiresBothExactNativeAuthorities(t *testing.T) {
	m := apacheNativeBodyManifestFixture()
	m.Version = ApacheNativeCCAppVersion
	m.RequiredPanelFeatures = []string{ApacheNativeBodySiteFeature, ApacheNativeCCSiteFeature}
	if err := validatePanelRequirements(m, func(s string) bool { return s == ApacheNativeBodySiteFeature || s == ApacheNativeCCSiteFeature }); err != nil {
		t.Fatal(err)
	}
	for _, feature := range []string{ApacheNativeBodySiteFeature, ApacheNativeCCSiteFeature} {
		if validatePanelRequirements(m, func(s string) bool { return s != feature }) == nil {
			t.Fatal("partial older handler acquired CC", feature)
		}
	}
	for _, mutate := range []func(*Manifest){
		func(v *Manifest) { v.Version = "2.5.0-alias" }, func(v *Manifest) { v.Version = "2.5.1" }, func(v *Manifest) { v.Version = "2.4.0" },
		func(v *Manifest) { v.ID = "nginx-waf" }, func(v *Manifest) { v.Delivery.Target = "nginx-waf" }, func(v *Manifest) { v.Delivery.Provider = "runtime" },
		func(v *Manifest) { v.RequiredPanelFeatures = []string{ApacheNativeBodySiteFeature} }, func(v *Manifest) { v.RequiredPanelFeatures = []string{ApacheNativeCCSiteFeature} }, func(v *Manifest) { v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, "caller") },
	} {
		v := m
		v.RequiredPanelFeatures = append([]string{}, m.RequiredPanelFeatures...)
		mutate(&v)
		if validatePanelRequirements(v, func(string) bool { return true }) == nil {
			t.Fatal("unknown native manifest accepted", v)
		}
	}
	if panelFeatureAvailable(ApacheNativeCCSiteFeature) != (runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")) {
		t.Fatal("CC advertised without its actual platform")
	}
	legacy := apacheNativeBodyManifestFixture()
	if err := validatePanelRequirements(legacy, func(s string) bool { return s == ApacheNativeBodySiteFeature }); err != nil {
		t.Fatal("unchanged old body-only signed manifest rejected", err)
	}
}
