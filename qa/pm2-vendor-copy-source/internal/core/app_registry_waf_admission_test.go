package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRegistryWAFUnhealthyLegacyRequiresConfigurationReviewWithoutGrantingUpdates(t *testing.T) {
	for _, version := range []string{"2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1"} {
		for _, healthy := range []bool{false, true} {
			t.Run(version+map[bool]string{false: "/drifted", true: "/healthy"}[healthy], func(t *testing.T) {
				store := testStore(t)
				before := replayCounts(t, store)
				executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Error("A read tried to mutate executor", r.Method, r.URL.Path)
						http.Error(w, "denied", 405)
						return
					}
					switch r.URL.Path {
					case "/v1/runtimes":
						w.Write([]byte(`{"installed":[]}`))
					case "/v1/docker/projects":
						w.Write([]byte(`{"projects":[]}`))
					case "/v1/software":
						json.NewEncoder(w).Encode([]SoftwareAppStatus{{ID: "nginx-waf", Version: version, Installed: true, Healthy: healthy, Detail: "Original configured/render fingerprint drift"}, {ID: "files-sync", Version: "1.0", Installed: true, Healthy: false}})
					default:
						http.NotFound(w, r)
					}
				})
				server := &Server{Store: store, Executor: executor}
				apps := appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "nginx-waf", Provider: "panel-module", Target: "nginx-waf", Stage: "ready", Version: WAFVersion}, {ID: "files-sync", Provider: "panel-module", Target: "files-sync", Stage: "ready", Version: "1.1.0"}}}
				rows := server.appRegistryStatuses(context.Background(), apps)
				if len(rows) != 2 {
					t.Fatal(rows)
				}
				got := rows[0]
				if !got.StateKnown || !got.Installed || !got.VersionKnown || got.InstalledVersion != version || !got.UpdateAvailable || got.Healthy != healthy {
					t.Fatal("The original version/health must stay visible", got)
				}
				if !got.Supported {
					if got.UpdateSupported || got.UpdateKind != "panel-upgrade" {
						t.Fatal("An unsupported host was treated as a configuration repair grant", got)
					}
				} else if !healthy {
					if got.UpdateSupported || got.UpdateKind != "waf-config-review" || !strings.Contains(got.UpdateDetail, "配置") || !strings.Contains(got.UpdateDetail, "未") {
						t.Fatal("Drifted old WAF falsely offered an automatic migration", got)
					}
				} else if got.UpdateKind != "module" || got.UpdateSupported != got.Supported {
					t.Fatal("Healthy legacy migration was disabled or invented", got)
				}
				otherKind := "module"
				if !rows[1].Supported {
					otherKind = "panel-upgrade"
				}
				if rows[1].UpdateKind != otherKind || rows[1].UpdateSupported != rows[1].Supported {
					t.Fatal("The WAF admission change escaped to another module", rows[1])
				}
				if after := replayCounts(t, store); !reflect.DeepEqual(before, after) {
					t.Fatal("Status fabricated a native job, binding, receipt or audit", before, after)
				}
			})
		}
	}
}

func TestRegistryWAFUnknownOrCurrentVersionNeverCreatesAnUpdateFromDrift(t *testing.T) {
	for _, state := range []SoftwareAppStatus{
		{ID: "nginx-waf", Version: WAFVersion, Installed: true, Healthy: false},
		{ID: "nginx-waf", Version: "2.0.1", Installed: true, Healthy: false, StateUnknown: true},
		{ID: "nginx-waf", Version: "invalid", Installed: true, Healthy: false},
		{ID: "nginx-waf", Version: "2.0.1", Installed: false, Healthy: false},
	} {
		executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/runtimes":
				w.Write([]byte(`{"installed":[]}`))
			case "/v1/docker/projects":
				w.Write([]byte(`{"projects":[]}`))
			case "/v1/software":
				json.NewEncoder(w).Encode([]SoftwareAppStatus{state})
			default:
				http.NotFound(w, r)
			}
		})
		server := &Server{Store: testStore(t), Executor: executor}
		rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "nginx-waf", Provider: "panel-module", Target: "nginx-waf", Stage: "ready", Version: WAFVersion}}})
		if len(rows) != 1 || rows[0].UpdateAvailable || rows[0].UpdateSupported || rows[0].UpdateKind != "" {
			t.Fatal("Unknown/current health drift fabricated a new update", rows)
		}
	}
}

func TestRegistryWAFConfigurationReviewChangesOnlyExactSupportedUnhealthyLegacyAdmission(t *testing.T) {
	app := appcatalog.CatalogItem{ID: "nginx-waf", Provider: "panel-module", Target: "nginx-waf", Stage: "ready", Version: WAFVersion}
	before := AppRegistryStatus{ID: app.ID, StateKnown: true, Installed: true, Healthy: false, Supported: true, InstalledVersion: "2.0.1", LatestVersion: WAFVersion, VersionKnown: true, UpdateAvailable: true, UpdateSupported: true, UpdateKind: "module", Detail: "original actual drift"}
	got := before
	applyRegistryWAFConfigurationReview(&got, app)
	if got.UpdateKind != "waf-config-review" || got.UpdateSupported || !strings.Contains(got.UpdateDetail, "配置") || !strings.Contains(got.UpdateDetail, "未修改") {
		t.Fatal("unsafe legacy migration still advertised", got)
	}
	got.UpdateKind, got.UpdateSupported, got.UpdateDetail = before.UpdateKind, before.UpdateSupported, before.UpdateDetail
	if !reflect.DeepEqual(got, before) {
		t.Fatal("review fabricated installation, health, version or capability evidence", got, before)
	}
	for name, change := range map[string]func(*AppRegistryStatus, *appcatalog.CatalogItem){
		"another-app":                          func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { a.ID = "apache-waf" },
		"another-target":                       func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { a.Target = "apache-waf" },
		"runtime":                              func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { a.Provider = "runtime" },
		"not-ready":                            func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { a.Stage = "integration" },
		"alias":                                func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { a.Version += "-alias" },
		"different-status":                     func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.ID = "apache-waf" },
		"stale-status":                         func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.LatestVersion = "2.5.1" },
		"unsupported":                          func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.Supported = false },
		"unknown-state":                        func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.StateKnown = false },
		"not-installed":                        func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.Installed = false },
		"unknown-version":                      func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.VersionKnown = false },
		"healthy":                              func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.Healthy = true },
		"no-update":                            func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.UpdateAvailable = false },
		"unavailable-handler-or-receipt-error": func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.UpdateSupported = false },
		"another-kind":                         func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.UpdateKind = "panel-upgrade" },
		"current":                              func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.InstalledVersion = WAFVersion },
		"future":                               func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.InstalledVersion = "99.0.0" },
		"invalid-version":                      func(s *AppRegistryStatus, a *appcatalog.CatalogItem) { s.InstalledVersion = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			s, a := before, app
			change(&s, &a)
			unchanged := s
			applyRegistryWAFConfigurationReview(&s, a)
			if !reflect.DeepEqual(s, unchanged) {
				t.Fatal("review escaped its exact guarded scope", unchanged, s)
			}
		})
	}
	applyRegistryWAFConfigurationReview(nil, app)
}

func TestRegistryWAFUnhealthyUpdateHTTPRefusesBeforeManifestPullOrQueue(t *testing.T) {
	// The signing key is an isolated fixture key, never the publisher key.
	// On supported Linux the actual complete status builder must return the
	// configuration-review reason; other hosts retain their compatibility denial.
	store := testStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var packageReads atomic.Int32
	var item appcatalog.CatalogItem
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/signatures/catalog-v1.bundle.json" {
			packageReads.Add(1)
			http.Error(w, "Manifest must not be fetched", 500)
			return
		}
		body, err := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: Now(), Apps: []appcatalog.CatalogItem{item}})
		if err != nil {
			t.Error(err)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"catalog": string(body), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
	}))
	defer upstream.Close()
	item = appcatalog.CatalogItem{ID: "nginx-waf", Name: "Nginx WAF", Category: "professional", Version: WAFVersion, Summary: "Exact private signature fixture only", Stage: "ready", Risk: "maintained", Provider: "panel-module", Target: "nginx-waf", ManageRoute: "security", Capabilities: []string{"WAF"}, SHA256: strings.Repeat("a", 64), PackageURL: upstream.URL + "/dist/apps/nginx-waf/" + WAFVersion + "/manifest.json"}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := appcatalog.New(upstream.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("Refused update called an executor mutation", r.Method, r.URL.Path)
			http.Error(w, "Denied", 405)
			return
		}
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[]}`))
		case "/v1/docker/projects":
			w.Write([]byte(`{"projects":[]}`))
		case "/v1/software":
			json.NewEncoder(w).Encode([]SoftwareAppStatus{{ID: "nginx-waf", Version: "2.0.1", Installed: true, Healthy: false, Detail: "Original loaded-render mismatch"}})
		default:
			http.NotFound(w, r)
		}
	})
	a := &Server{Store: store, AppCatalog: catalog, Executor: executor, Config: Config{DataDir: t.TempDir()}}
	before := replayCounts(t, store)
	rows := a.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{item}})
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/app-registry/nginx-waf/update", strings.NewReader(`{"expected_version":"`+WAFVersion+`","expected_sha256":"`+item.SHA256+`"}`))
	request.SetPathValue("id", "nginx-waf")
	request.Header.Set("Idempotency-Key", "waf-configuration-review")
	response := httptest.NewRecorder()
	a.updateRegistryApp(response, request, identity{ID: ID(), Username: "private-fixture-admin"})
	if response.Code != http.StatusConflict || packageReads.Load() != 0 || !reflect.DeepEqual(before, replayCounts(t, store)) {
		t.Fatal("Unhealthy migration fetched or queued a package", response.Code, response.Body.String(), packageReads.Load(), before, replayCounts(t, store))
	}
	if rows[0].Supported && (!strings.Contains(response.Body.String(), "配置") || rows[0].UpdateKind != "waf-config-review") {
		t.Fatal("The supported-host refusal hid the actual configuration prerequisite", rows[0], response.Body.String())
	}
}
