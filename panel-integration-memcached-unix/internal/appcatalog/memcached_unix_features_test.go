package appcatalog

import (
	"runtime"
	"testing"
)

func memcachedUnixFixture() Manifest {
	m := memcachedDigestFixture()
	m.Version = MemcachedUnixVersion
	m.RequiredPanelFeatures = []string{MemcachedDigestFeature, MemcachedUnixFeature}
	return m
}

func TestMemcachedUnixRequiresIndependentClosedPackageAndHandlers(t *testing.T) {
	m := memcachedUnixFixture()
	if !IsMemcachedUnixManifest(m) || validatePanelRequirements(m, func(f string) bool { return f == MemcachedDigestFeature || f == MemcachedUnixFeature }) != nil {
		t.Fatal("closed Unix profile refused")
	}
	for _, missing := range []string{MemcachedDigestFeature, MemcachedUnixFeature} {
		if validatePanelRequirements(m, func(f string) bool { return f != missing }) == nil {
			t.Fatal("missing independent handler accepted")
		}
	}
	for name, change := range map[string]func(*Manifest){
		"old-version":    func(m *Manifest) { m.Version = "1.6.45-compat3" },
		"future-version": func(m *Manifest) { m.Version = "1.6.45-compat5" },
		"foreign-app":    func(m *Manifest) { m.ID = "mongodb" },
		"target":         func(m *Manifest) { m.Delivery.Target = "redis-cache" },
		"route":          func(m *Manifest) { m.Delivery.ManageRoute = "files" },
		"provider":       func(m *Manifest) { m.Delivery.Provider = "native" },
		"tag-only":       func(m *Manifest) { m.Delivery.Image = "memcached:1.6.45-alpine" },
		"missing":        func(m *Manifest) { m.RequiredPanelFeatures = []string{MemcachedDigestFeature} },
		"old-prototype": func(m *Manifest) {
			m.RequiredPanelFeatures = []string{MemcachedDigestFeature, "compose-memcached-sandbox-v1"}
		},
		"duplicate": func(m *Manifest) { m.RequiredPanelFeatures = []string{MemcachedUnixFeature, MemcachedUnixFeature} },
	} {
		t.Run(name, func(t *testing.T) {
			v := m
			change(&v)
			if IsMemcachedUnixManifest(v) || validatePanelRequirements(v, func(string) bool { return true }) == nil {
				t.Fatal("foreign identity borrowed Unix profile")
			}
		})
	}
}

func TestMemcachedUnpublishedInternalTCPPrototypeIsNotAnAvailableHandler(t *testing.T) {
	if panelFeatureAvailable("compose-memcached-sandbox-v1") {
		t.Fatal("actual failed TCP/internal prototype must not be advertised")
	}
	if panelFeatureAvailable(MemcachedUnixFeature) != (runtime.GOOS == "linux") {
		t.Fatal("Unix handlers must be limited to the compiled Linux implementation")
	}
	prototype := memcachedDigestFixture()
	prototype.Version = "1.6.45-compat3"
	prototype.RequiredPanelFeatures = []string{MemcachedDigestFeature, "compose-memcached-sandbox-v1"}
	if validatePanelRequirements(prototype, panelFeatureAvailable) == nil {
		t.Fatal("withdrawn prototype authorized an installation")
	}
	if (validatePanelRequirements(memcachedUnixFixture(), panelFeatureAvailable) == nil) != (runtime.GOOS == "linux") {
		t.Fatal("exact independent Unix handlers have the wrong platform availability")
	}
	if handled, _ := validateMemcachedUnixRequirement(memcachedDigestFixture(), nil); handled {
		t.Fatal("published compat2 reinterpreted")
	}
}
