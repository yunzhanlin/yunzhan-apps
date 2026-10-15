package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func memcachedDigestFixture() Manifest {
	m := panelRequirementFixture()
	m.ID, m.Name, m.Version, m.Category = "memcached", "Memcached", "1.1.0", "deployment"
	m.Delivery = Delivery{Provider: "compose", Target: "memcached-cache", Image: MemcachedDigestImage, ManageRoute: "docker"}
	m.RequiredPanelFeatures = []string{MemcachedDigestFeature}
	return m
}

func TestMemcachedDigestRequirementBindsExactImageAndClosedComposeABI(t *testing.T) {
	if err := validatePanelRequirements(memcachedDigestFixture(), func(f string) bool { return f == MemcachedDigestFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(memcachedDigestFixture(), available); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("old tag-only handler authorized future digest app", err)
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "extra", "unknown", "other-app", "other-target", "other-route", "runtime", "panel-module", "isolation", "tag-only", "different-digest", "different-tag", "alias", "future", "old-version"} {
		t.Run(scenario, func(t *testing.T) {
			m := memcachedDigestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "duplicate":
				m.RequiredPanelFeatures = []string{MemcachedDigestFeature, MemcachedDigestFeature}
			case "extra":
				m.RequiredPanelFeatures = []string{MemcachedDigestFeature, DiskHostJobsFeature}
			case "unknown":
				m.RequiredPanelFeatures = []string{"compose-anything-v1"}
			case "other-app":
				m.ID = "mongodb"
			case "other-target":
				m.Delivery.Target = "mongodb"
			case "other-route":
				m.Delivery.ManageRoute = "app-modules"
			case "runtime", "panel-module":
				m.Delivery.Provider = scenario
			case "isolation":
				m.Delivery.Isolation = "legacy-container"
			case "tag-only":
				m.Delivery.Image = "memcached:1.6.45-alpine"
			case "different-digest":
				m.Delivery.Image = "memcached:1.6.45-alpine@sha256:" + strings.Repeat("a", 64)
			case "different-tag":
				m.Delivery.Image = strings.Replace(MemcachedDigestImage, "1.6.45-alpine", "latest", 1)
			case "alias":
				m.Version = "1.1.0-compat1"
			case "future":
				m.Version = "1.2.0"
			case "old-version":
				m.Version = "1.0.0"
			}
			if validatePanelRequirements(m, func(string) bool { return true }) == nil {
				t.Fatal("unbound digest capability admitted")
			}
		})
	}
}

func TestMemcachedDigestRequirementDoesNotBroadenOtherProvidersOrOldPackage(t *testing.T) {
	m := memcachedDigestFixture()
	m.Version, m.RequiredPanelFeatures, m.Delivery.Image = "1.0.0", nil, "memcached:1.6.45-alpine"
	if err := validatePanelRequirements(m, nil); err != nil {
		t.Fatal("historical immutable package rejected", err)
	}
	for _, provider := range []string{"compose", "runtime"} {
		m := maintenanceRequirementFixture()
		m.Delivery.Provider = provider
		if validatePanelRequirements(m, func(string) bool { return true }) == nil {
			t.Fatal("old provider feature gate broadened", provider)
		}
	}
}

func TestMemcachedDigestManifestBytesCannotBorrowNewHandlerClaim(t *testing.T) {
	m := memcachedDigestFixture()
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://example.invalid/dist/apps/memcached/1.1.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	c := &Client{BaseURL: "https://example.invalid"}
	if _, err := c.verifyManifestData(item, raw); (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("actual compiled OS feature availability ignored", err)
	}
	m.RequiredPanelFeatures = nil
	changed, _ := json.Marshal(m)
	if _, err := c.verifyManifestData(item, changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("changed manifest borrowed original digest", err)
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	if _, err := c.verifyManifestData(item, changed); err == nil {
		t.Fatal("new package omitted mandatory digest handler")
	}
}
