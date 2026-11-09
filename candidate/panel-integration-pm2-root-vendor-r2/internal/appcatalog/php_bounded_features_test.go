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

func phpBoundedFixture(id string) Manifest {
	version, _ := phpSecurityBinding(id)
	return Manifest{ID: id, Version: version + "-compat2", Delivery: Delivery{Provider: "runtime", Target: "php-" + version, ManageRoute: "runtimes"}, RequiredPanelFeatures: []string{PHPSecurity20261021Feature, PHPBoundedNativeBuildFeature}}
}

// Both network/cache pulls and the executor's offline verification must bind
// the complete manifest bytes before checking the two independently compiled
// handlers. Rehashing a stripped declaration must not turn it into compat1.
func TestPHPBoundedBuildManifestBytesBindOfflineNetworkAndCachedVerification(t *testing.T) {
	for _, id := range []string{"php-82", "php-83", "php-84", "php-85"} {
		t.Run(id, func(t *testing.T) {
			m := phpBoundedFixture(id)
			m.SchemaVersion, m.Name, m.Category, m.Stage, m.Risk = 1, "PHP bounded build fixture", "deployment", "ready", "maintained"
			m.Summary, m.Capabilities = "Manifest authority model, not installed acceptance", []string{"install"}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/dist/apps/"+id+"/"+m.Version+"/manifest.json" {
					t.Error("unexpected package path", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			client := &Client{BaseURL: server.URL, HTTP: server.Client()}
			digest := sha256.Sum256(raw)
			item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: server.URL + "/dist/apps/" + id + "/" + m.Version + "/manifest.json", SHA256: hex.EncodeToString(digest[:])}
			_, err = client.verifyManifestData(item, raw)
			if (err == nil) != (runtime.GOOS == "linux") {
				t.Fatal("offline compiled-handler authority ignored", err)
			}
			cache := filepath.Join(t.TempDir(), "packages")
			_, err = client.FetchManifest(context.Background(), item, cache)
			if (err == nil) != (runtime.GOOS == "linux") || calls.Load() != 1 {
				t.Fatal("network compiled-handler authority ignored", err, calls.Load())
			}
			if runtime.GOOS != "linux" {
				return
			}
			server.Close()
			if _, err := client.FetchManifest(context.Background(), item, cache); err != nil || calls.Load() != 1 {
				t.Fatal("offline cache refetched or lost authority", err, calls.Load())
			}
			m.RequiredPanelFeatures = []string{PHPSecurity20261021Feature}
			changed, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cache, id, m.Version, "manifest.json"), changed, 0600); err != nil {
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
					t.Fatal("stripped handler borrowed signed original bytes", cached, err)
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
				if err == nil || !strings.Contains(err.Error(), "compat2") {
					t.Fatal("rehash replaced required bounded builder", cached, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("invalid cached authority triggered a network fallback")
			}
		})
	}
}

func TestPHPBoundedBuildRequiresBothIndependentCompiledHandlers(t *testing.T) {
	for _, id := range []string{"php-82", "php-83", "php-84", "php-85"} {
		for _, reverse := range []bool{false, true} {
			m := phpBoundedFixture(id)
			if reverse {
				m.RequiredPanelFeatures[0], m.RequiredPanelFeatures[1] = m.RequiredPanelFeatures[1], m.RequiredPanelFeatures[0]
			}
			if err := validatePanelRequirements(m, func(feature string) bool {
				return feature == PHPSecurity20261021Feature || feature == PHPBoundedNativeBuildFeature
			}); err != nil {
				t.Fatal(id, err)
			}
			for _, missing := range []string{PHPSecurity20261021Feature, PHPBoundedNativeBuildFeature} {
				if err := validatePanelRequirements(m, func(feature string) bool { return feature != missing }); err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "请先升级面板") {
					t.Fatal("missing independently compiled handler was borrowed", id, missing, err)
				}
			}
			if err := validatePanelRequirements(m, nil); err == nil {
				t.Fatal("absent compiled handler inventory admitted compat2")
			}
		}
	}
	if panelFeatureAvailable(PHPBoundedNativeBuildFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("php-bounded-native-build-v2") {
		t.Fatal("bounded builder capability widened to unsupported host/revision")
	}
}

func TestPHPBoundedBuildCannotBeBorrowedByLabelsTargetsOrOtherApplications(t *testing.T) {
	for _, id := range []string{"php-82", "php-83", "php-84", "php-85"} {
		for _, mutation := range []string{"missing", "empty", "security-only", "bounded-only", "duplicate-security", "duplicate-bounded", "extra", "future-feature", "compat1-label", "bare-label", "future-label", "noncanonical-label", "wrong-branch", "foreign-id", "foreign-unrelated-target", "foreign-no-feature", "old-target", "other-patched-target", "provider", "route"} {
			t.Run(id+"/"+mutation, func(t *testing.T) {
				m := phpBoundedFixture(id)
				version, _ := phpSecurityBinding(id)
				switch mutation {
				case "missing":
					m.RequiredPanelFeatures = nil
				case "empty":
					m.RequiredPanelFeatures = []string{}
				case "security-only":
					m.RequiredPanelFeatures = []string{PHPSecurity20261021Feature}
				case "bounded-only":
					m.RequiredPanelFeatures = []string{PHPBoundedNativeBuildFeature}
				case "duplicate-security":
					m.RequiredPanelFeatures = []string{PHPSecurity20261021Feature, PHPSecurity20261021Feature}
				case "duplicate-bounded":
					m.RequiredPanelFeatures = []string{PHPBoundedNativeBuildFeature, PHPBoundedNativeBuildFeature}
				case "extra":
					m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, NativeMobileDeliveryFeature)
				case "future-feature":
					m.RequiredPanelFeatures[1] = "php-bounded-native-build-v2"
				case "compat1-label":
					m.Version = version + "-compat1"
				case "bare-label":
					m.Version = version
				case "future-label":
					m.Version = version + "-compat3"
				case "noncanonical-label":
					m.Version = version + "-compat02"
				case "wrong-branch":
					m.ID = "php-81"
				case "foreign-id":
					m.ID = "daily-report"
				case "foreign-unrelated-target":
					m.ID, m.Delivery.Target = "daily-report", "daily-report"
				case "foreign-no-feature":
					m.ID, m.RequiredPanelFeatures = "daily-report", nil
				case "old-target":
					m.Delivery.Target = "php-8.2.33"
				case "other-patched-target":
					m.Delivery.Target = "php-8.2.35"
					if id == "php-82" {
						m.Delivery.Target = "php-8.3.36"
					}
				case "provider":
					m.Delivery.Provider = "panel-module"
				case "route":
					m.Delivery.ManageRoute = "sites"
				}
				if err := validatePanelRequirements(m, func(string) bool { return true }); err == nil {
					t.Fatal("unknown or borrowed bounded build capability admitted", id, mutation)
				}
			})
		}
	}
}
