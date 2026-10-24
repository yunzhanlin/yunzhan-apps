//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func TestMobileSelectedVersionSinkPreservesLegacyAndRefusesInstallOverwrite(t *testing.T) {
	for _, version := range []string{"", "1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", "1.3.2"} {
		t.Run(version, func(t *testing.T) {
			s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security"), Run: func(context.Context, string, ...string) (string, error) {
				t.Error("mobile record install must not execute host command")
				return "", errors.New("excluded")
			}})
			if err := s.appModuleLifecycleVersion(context.Background(), "mobile-pwa", "install", map[string]any{}, version, func(string) {}); err != nil {
				t.Fatal(err)
			}
			want := version
			if want == "" {
				want = "1.3.0"
			}
			old, err := s.moduleInstalledRecord("mobile-pwa")
			if err != nil || old["version"] != want {
				t.Fatal("old package promoted at record sink", old, err)
			}
			path := filepath.Join(s.moduleDir("mobile-pwa"), "installed.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.appModuleLifecycleVersion(context.Background(), "mobile-pwa", "install", map[string]any{}, core.NativeMobileAppVersion, func(string) {}); err == nil {
				t.Fatal("install overwrote existing identity")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused install modified old record", err)
			}
			if err := s.appModuleLifecycle(context.Background(), "mobile-pwa", "configure", map[string]any{"enabled": true}, func(string) {}); err != nil {
				t.Fatal(err)
			}
			configured, err := s.moduleInstalledRecord("mobile-pwa")
			if err != nil || configured["version"] != want || configured["installed_at"] != old["installed_at"] || configured["updated_at"] != old["updated_at"] {
				t.Fatal("configuration save impersonated update", configured, err)
			}
		})
	}
	for _, version := range []string{"1.3.1", "1.3.2-compat1", "01.3.2", "1.3.3", "unknown"} {
		t.Run("refuse/"+version, func(t *testing.T) {
			security := filepath.Join(t.TempDir(), "security")
			s := New(Config{SecurityDir: security})
			if err := s.appModuleLifecycleVersion(context.Background(), "mobile-pwa", "install", nil, version, func(string) {}); err == nil {
				t.Fatal("unknown native version accepted")
			}
			if _, err := os.Lstat(security); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid version wrote before refusal", err)
			}
		})
	}
}

// Actual authenticated Core -> verified private Ed25519 catalog/manifest ->
// immutable SQLite queue -> normal worker -> real Unix executor -> private
// installed.json -> actual store reconciliation/update. Only runtime/docker
// inventory are empty fixture responses. No daemon or installed host app is
// changed. This proves the integration contract, not live GitHub publication,
// a physical mobile device or a production application installation.
func TestSignedMobileCoreUnixExactInstallAndExplicitStoreUpdate(t *testing.T) {
	for _, initial := range []string{"1.0", "1.3.0", core.NativeMobileAppVersion} {
		t.Run(initial, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			base := t.TempDir()
			for _, dir := range []string{"security", "data", "web", "state", "sites", "conf", "system"} {
				if err := os.Mkdir(filepath.Join(base, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			svc := New(Config{SecurityDir: filepath.Join(base, "security"), StateDir: filepath.Join(base, "state"), SitesDir: filepath.Join(base, "sites"), ConfDir: filepath.Join(base, "conf"), SystemRoot: filepath.Join(base, "system"), Run: func(context.Context, string, ...string) (string, error) {
				return "", errors.New("private version fixture refuses every host command")
			}})
			store, err := core.OpenStore(filepath.Join(base, "data/panel.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.DB.Close()
			socket := filepath.Join(base, "e.sock")
			panel, err := core.NewServer(store, core.Config{DataDir: filepath.Join(base, "data"), WebDir: filepath.Join(base, "web"), Origin: "http://127.0.0.1:19564", Socket: socket})
			if err != nil {
				t.Fatal(err)
			}
			defer panel.Executor.Client.CloseIdleConnections()
			listener, err := net.Listen("unix", socket)
			if err != nil || os.Chmod(socket, 0600) != nil {
				t.Fatal("private Unix executor", err)
			}
			var installs atomic.Int32
			handler := svc.Handler()
			execHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/v1/runtimes" {
					respond(w, 200, map[string]any{"installed": []any{}})
					return
				}
				if r.Method == "GET" && r.URL.Path == "/v1/docker/projects" {
					respond(w, 200, map[string]any{"projects": []any{}})
					return
				}
				if r.Method == "GET" && r.URL.Path == "/v1/software" {
					handler.ServeHTTP(w, r)
					return
				}
				if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/software/mobile-pwa/") {
					if r.URL.Path == "/v1/software/mobile-pwa/install" {
						installs.Add(1)
					}
					handler.ServeHTTP(w, r)
					return
				}
				http.Error(w, "excluded fixture endpoint", 503)
			})}
			go func() { _ = execHTTP.Serve(listener) }()
			defer execHTTP.Close()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			current := initial
			manifests := map[string][]byte{}
			var currentItem appcatalog.CatalogItem
			var upstream *httptest.Server
			setVersion := func(version string) {
				mu.Lock()
				defer mu.Unlock()
				current = version
				m := appcatalog.Manifest{SchemaVersion: 1, ID: "mobile", Name: "Private mobile version fixture", Category: "professional", Version: version, Summary: "Private exact signed version identity integration,not production acceptance", Stage: "ready", Risk: "normal", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "mobile-pwa", ManageRoute: "app-modules"}, Compatibility: appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}}, Capabilities: []string{"install", "update"}}
				if version == core.NativeMobileAppVersion {
					m.RequiredPanelFeatures = []string{appcatalog.NativeMobileDeliveryFeature}
				}
				raw, e := json.Marshal(m)
				if e != nil {
					t.Fatal(e)
				}
				manifests[version] = raw
				currentItem = appcatalog.CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: upstream.URL + "/dist/apps/mobile/" + version + "/manifest.json", SHA256: core.Hash(string(raw))}
			}
			upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/signatures/catalog-v1.bundle.json" {
					raw, e := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: core.Now(), Apps: []appcatalog.CatalogItem{currentItem}})
					if e != nil {
						http.Error(w, "marshal", 500)
						return
					}
					json.NewEncoder(w).Encode(map[string]string{"catalog": string(raw), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))})
					return
				}
				for version, raw := range manifests {
					if r.URL.Path == "/dist/apps/mobile/"+version+"/manifest.json" {
						w.Write(raw)
						return
					}
				}
				http.NotFound(w, r)
			}))
			defer upstream.Close()
			setVersion(initial)
			der, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			panel.AppCatalog, err = appcatalog.New(upstream.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), upstream.Client())
			if err != nil {
				t.Fatal(err)
			}
			var cookie *http.Cookie
			csrf := ""
			request := func(method, path, key string, body any) *httptest.ResponseRecorder {
				raw, e := json.Marshal(body)
				if e != nil {
					t.Fatal(e)
				}
				if body == nil {
					raw = nil
				}
				r := httptest.NewRequestWithContext(ctx, method, panel.Config.Origin+path, bytes.NewReader(raw))
				r.Header.Set("Origin", panel.Config.Origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("Idempotency-Key", key)
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				panel.ServeHTTP(w, r)
				return w
			}
			token, err := os.ReadFile(filepath.Join(base, "data/bootstrap-token"))
			if err != nil {
				t.Fatal(err)
			}
			if r := request("POST", "/api/bootstrap", "", map[string]string{"username": "version-owner", "password": "private-version-password-long", "token": strings.TrimSpace(string(token))}); r.Code != 201 {
				t.Fatal("bootstrap", r.Code, r.Body.String())
			}
			login := request("POST", "/api/login", "", map[string]string{"username": "version-owner", "password": "private-version-password-long"})
			var auth struct {
				CSRF string `json:"csrf"`
			}
			if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(login.Result().Cookies()) != 1 {
				t.Fatal("actual login", login.Code)
			}
			csrf = auth.CSRF
			cookie = login.Result().Cookies()[0]
			defer func() {
				if r := request("POST", "/api/logout", "", map[string]any{}); r.Code != 200 {
					t.Error("private session logout", r.Code)
				}
			}()
			jobID := func(r *httptest.ResponseRecorder) string {
				var out struct {
					ID string `json:"job_id"`
				}
				if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &out) != nil || !core.ValidID(out.ID) {
					t.Fatal("normal queue", r.Code, r.Body.String())
				}
				return out.ID
			}
			pins := func() map[string]any {
				mu.Lock()
				defer mu.Unlock()
				return map[string]any{"expected_version": currentItem.Version, "expected_sha256": currentItem.SHA256, "settings": map[string]any{}}
			}
			originalInput := pins()
			installID := jobID(request("POST", "/api/app-registry/mobile/install", "original-install", originalInput))
			var originalPayload, originalHash string
			if err := store.DB.QueryRow(`SELECT j.payload,i.job_payload_sha256 FROM runtime_jobs j JOIN app_registry_install_requests i ON i.job_id=j.id WHERE j.id=?`, installID).Scan(&originalPayload, &originalHash); err != nil || originalHash != core.Hash(originalPayload) || !strings.Contains(originalPayload, `"version":"`+initial+`"`) {
				t.Fatal("signed queue dropped version", originalPayload, err)
			}
			workerCtx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() { core.RunWorker(workerCtx, store, panel.Executor); close(done) }()
			defer func() {
				stop()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("private worker did not stop")
				}
			}()
			wait := func(id, want string) {
				for ctx.Err() == nil {
					var state, detail string
					if err := store.DB.QueryRow(`SELECT state,error FROM runtime_jobs WHERE id=?`, id).Scan(&state, &detail); err != nil {
						t.Fatal(err)
					}
					if state == want {
						return
					}
					if state != "queued" && state != "running" {
						t.Fatal("actual worker outcome", state, detail, want)
					}
					select {
					case <-ctx.Done():
					case <-time.After(5 * time.Millisecond):
					}
				}
				t.Fatal("private original20second context", ctx.Err())
			}
			wait(installID, "succeeded")
			record := func() map[string]any {
				v, e := svc.moduleInstalledRecord("mobile-pwa")
				if e != nil {
					t.Fatal(e)
				}
				return v
			}
			old := record()
			if old["version"] != initial {
				t.Fatal("signed old package promoted at installed sink", old)
			}
			registry := func(refresh bool) core.AppRegistryStatus {
				path := "/api/app-registry"
				if refresh {
					path += "?refresh=1"
				}
				r := request("GET", path, "", nil)
				var page core.AppRegistryPage
				if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || len(page.Status) != 1 {
					t.Fatal("actual registry reconciliation", r.Code, r.Body.String())
				}
				return page.Status[0]
			}
			row := registry(false)
			if !row.StateKnown || !row.Installed || !row.VersionKnown || !row.Healthy || row.InstalledVersion != initial {
				t.Fatal("store invented package identity", row)
			}
			var receiptVersion, receiptSHA string
			if e := store.DB.QueryRow(`SELECT version,sha256 FROM app_registry_receipts WHERE app_id='mobile'`).Scan(&receiptVersion, &receiptSHA); e != nil || receiptVersion != initial || receiptSHA != originalInput["expected_sha256"] {
				t.Fatal("signed receipt mismatched real record", receiptVersion, e)
			}
			if replay := jobID(request("POST", "/api/app-registry/mobile/install", "original-install", originalInput)); replay != installID || installs.Load() != 1 {
				t.Fatal("completed install replayed", replay, installs.Load())
			}
			path := filepath.Join(svc.moduleDir("mobile-pwa"), "installed.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			duplicate := jobID(request("POST", "/api/app-registry/mobile/install", "duplicate-install", originalInput))
			wait(duplicate, "failed")
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("duplicate install rewrote old version", err)
			}
			configure := jobID(request("POST", "/api/software/mobile-pwa/configure", "original-configure", map[string]any{"settings": map[string]any{"enabled": true}}))
			wait(configure, "succeeded")
			configured := record()
			if configured["version"] != initial || configured["installed_at"] != old["installed_at"] || configured["updated_at"] != old["updated_at"] {
				t.Fatal("configuration impersonated version update", configured)
			}
			if initial != core.NativeMobileAppVersion {
				setVersion(core.NativeMobileAppVersion)
				row = registry(true)
				if row.InstalledVersion != initial || row.LatestVersion != core.NativeMobileAppVersion || !row.UpdateAvailable || !row.UpdateSupported {
					t.Fatal("actual store hid genuine native update", row)
				}
				mu.Lock()
				updateInput := map[string]string{"expected_version": current, "expected_sha256": currentItem.SHA256}
				mu.Unlock()
				updateID := jobID(request("POST", "/api/app-registry/mobile/update", "explicit-native-update", updateInput))
				wait(updateID, "succeeded")
				row = registry(false)
				updated := record()
				if updated["version"] != core.NativeMobileAppVersion || updated["installed_at"] != old["installed_at"] || updated["updated_at"] == nil || updated["settings"].(map[string]any)["enabled"] != true || row.UpdateAvailable || row.InstalledVersion != core.NativeMobileAppVersion {
					t.Fatal("explicit update lost settings or store identity", updated, row)
				}
			}
			var retainedPayload, retainedHash string
			if e := store.DB.QueryRow(`SELECT j.payload,i.job_payload_sha256 FROM runtime_jobs j JOIN app_registry_install_requests i ON i.job_id=j.id WHERE j.id=?`, installID).Scan(&retainedPayload, &retainedHash); e != nil || retainedPayload != originalPayload || retainedHash != originalHash {
				t.Fatal("later configure/update relabelled original request", e)
			}
		})
	}
}
