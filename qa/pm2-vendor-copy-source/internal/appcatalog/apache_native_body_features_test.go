package appcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func apacheNativeBodyManifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, ID: "apache-waf", Name: "Apache native body fixture", Category: "professional", Version: ApacheNativeBodyAppVersion, Stage: "ready", Risk: "maintained", Summary: "Private manifest authority model,not installed protection", Capabilities: []string{"native body transactions"}, Delivery: Delivery{Provider: "panel-module", Target: "apache-waf", ManageRoute: "app-modules"}, RequiredPanelFeatures: []string{ApacheNativeBodySiteFeature}}
}

func TestApacheNativeBodyFeatureRequiresExactIndependentHandler(t *testing.T) {
	m := apacheNativeBodyManifestFixture()
	if err := validatePanelRequirements(m, func(f string) bool { return f == ApacheNativeBodySiteFeature }); err != nil {
		t.Fatal(err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if err := validatePanelRequirements(m, available); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
			t.Fatal("older handler admitted native body label", err)
		}
	}
	for _, scenario := range []string{"missing", "empty", "duplicate", "extra", "wrong-feature", "alias", "future", "leading-zero", "overflow", "unknown", "legacy-feature", "foreign-id", "foreign-no-feature", "target", "route", "runtime", "compose"} {
		t.Run(scenario, func(t *testing.T) {
			m := apacheNativeBodyManifestFixture()
			switch scenario {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "empty":
				m.RequiredPanelFeatures = []string{}
			case "duplicate":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, ApacheNativeBodySiteFeature)
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, WAFBoundHealthFeature)
			case "wrong-feature":
				m.RequiredPanelFeatures = []string{WAFBoundHealthFeature}
			case "alias":
				m.Version = "2.4.0-compat1"
			case "future":
				m.Version = "2.5.0"
			case "leading-zero":
				m.Version = "02.4.0"
			case "overflow":
				m.Version = "18446744073709551616.0.0"
			case "unknown":
				m.Version = "unknown"
			case "legacy-feature":
				m.Version = "2.3.0"
			case "foreign-id":
				m.ID = "daily-report"
			case "foreign-no-feature":
				m.ID = "daily-report"
				m.RequiredPanelFeatures = nil
			case "target":
				m.Delivery.Target = "nginx-waf"
			case "route":
				m.Delivery.ManageRoute = "security"
			case "runtime", "compose":
				m.Delivery.Provider = scenario
			}
			if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
				t.Fatal("borrowed native Apache capability", scenario)
			}
		})
	}
}

func TestApacheNativeBodyFeaturePreservesLegacyAndLinuxBoundary(t *testing.T) {
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0"} {
		m := apacheNativeBodyManifestFixture()
		m.Version = version
		m.RequiredPanelFeatures = nil
		if err := validatePanelRequirements(m, nil); err != nil {
			t.Fatal("published predecessor changed identity", version, err)
		}
	}
	if panelFeatureAvailable(ApacheNativeBodySiteFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("apache-native-body-site-transactions-v2") {
		t.Fatal("Apache native handler scope widened")
	}
}

func TestApacheNativeBodyFeatureManifestBytesBindOfflineNetworkAndCache(t *testing.T) {
	m := apacheNativeBodyManifestFixture()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/dist/apps/apache-waf/2.4.0/manifest.json" {
			t.Error("foreign package path", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, HTTP: server.Client()}
	digest := sha256.Sum256(raw)
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: server.URL + "/dist/apps/apache-waf/2.4.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	_, err = client.verifyManifestData(item, raw)
	if (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("offline handler check ignored", err)
	}
	cache := filepath.Join(t.TempDir(), "packages")
	_, err = client.FetchManifest(context.Background(), item, cache)
	if (err == nil) != (runtime.GOOS == "linux") || calls.Load() != 1 {
		t.Fatal("network handler check ignored", err, calls.Load())
	}
	if runtime.GOOS != "linux" {
		return
	}
	server.Close()
	if _, err := client.FetchManifest(context.Background(), item, cache); err != nil || calls.Load() != 1 {
		t.Fatal("verified cache did not work offline", err, calls.Load())
	}
	m.RequiredPanelFeatures = nil
	changed, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, m.ID, m.Version, "manifest.json"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	for _, cached := range []bool{false, true} {
		var err error
		if cached {
			_, err = client.FetchManifest(context.Background(), item, cache)
		} else {
			_, err = client.verifyManifestData(item, changed)
		}
		if err == nil || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatal("stripped handler borrowed original complete manifest bytes", cached, err)
		}
	}
	digest = sha256.Sum256(changed)
	item.SHA256 = hex.EncodeToString(digest[:])
	for _, cached := range []bool{false, true} {
		var err error
		if cached {
			_, err = client.FetchManifest(context.Background(), item, cache)
		} else {
			_, err = client.verifyManifestData(item, changed)
		}
		if err == nil || !strings.Contains(err.Error(), "2.4.0") {
			t.Fatal("rehash replaced required compiled native handler", cached, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid cache triggered network fallback")
	}
}
