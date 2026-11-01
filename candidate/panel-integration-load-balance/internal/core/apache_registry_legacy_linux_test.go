//go:build linux

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

// Exercise the real signed registry/Core handler. This temporary-key queue
// fixture does not install an application or grant a live engine receipt.
func TestApacheRegistrySignedLegacyAndNativeInstallOriginal(t *testing.T) {
	for _, version := range []string{"2.3.0", "2.4.0"} {
		t.Run(version, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "apache-signed-admin", "admin", nil)
			m := appcatalog.Manifest{SchemaVersion: 1, ID: "apache-waf", Name: "Apache WAF", Category: "professional", Version: version, Summary: "Exact signed Apache original request fixture", Stage: "ready", Risk: "normal", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "apache-waf", ManageRoute: "app-modules"}, Compatibility: appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}}, Capabilities: []string{"install"}}
			if version == "2.4.0" {
				m.RequiredPanelFeatures = []string{appcatalog.ApacheNativeBodySiteFeature}
			}
			manifest, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var item appcatalog.CatalogItem
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/signatures/catalog-v1.bundle.json":
					catalog, _ := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: Now(), Apps: []appcatalog.CatalogItem{item}})
					json.NewEncoder(w).Encode(map[string]string{"catalog": string(catalog), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalog))})
				case "/dist/apps/apache-waf/" + version + "/manifest.json":
					w.Write(manifest)
				default:
					http.NotFound(w, r)
				}
			}))
			defer host.Close()
			item = appcatalog.CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: host.URL + "/dist/apps/apache-waf/" + version + "/manifest.json", SHA256: Hash(string(manifest))}
			der, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := appcatalog.New(host.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), host.Client())
			if err != nil {
				t.Fatal(err)
			}
			a := &Server{Store: s, AppCatalog: catalog, Config: Config{DataDir: t.TempDir()}}
			in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
			result := installReplayHTTP(a, "apache-waf", "apache-signed-exact-version", u, in)
			var accepted struct {
				JobID string `json:"job_id"`
			}
			if result.Code != 202 || json.Unmarshal(result.Body.Bytes(), &accepted) != nil || !ValidID(accepted.JobID) {
				t.Fatal("exact signed Apache install did not enqueue its original", result.Code, result.Body.String())
			}
			var raw, target, kind string
			if err := s.DB.QueryRow(`SELECT payload,target_id,kind FROM runtime_jobs WHERE id=?`, accepted.JobID).Scan(&raw, &target, &kind); err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Version  string         `json:"version"`
				Settings map[string]any `json:"settings"`
			}
			if json.Unmarshal([]byte(raw), &payload) != nil || payload.Version != version || target != "apache-waf" || kind != "software_install" || payload.Settings == nil || payload.Settings["body"] != nil {
				t.Fatal("signed package identity or legacy metadata configuration changed", raw, target, kind)
			}
			original, err := s.readWAFApplyOriginal("apache-waf", u.ID, accepted.JobID)
			if err != nil || !original.ReadOnly || !original.Request.SignedInstall || original.Request.PayloadSHA != registryInstallDigest([]byte(raw)) {
				t.Fatal("exact signed Apache original cannot be observed read-only", err)
			}
			request, err := softwareExecutorPayload("apache-waf", accepted.JobID, payload.Settings, payload.Version)
			if err != nil || request["version"] != version {
				t.Fatal("privileged dispatch changed the selected package version", err)
			}
			var bindings int
			if err := s.DB.QueryRow(`SELECT count(*) FROM waf_apply_requests WHERE job_id=? AND actor_id=? AND app_id='apache-waf' AND kind='software_install' AND idempotency_key=? AND payload_sha256=?`, accepted.JobID, u.ID, "apache-signed-exact-version", registryInstallDigest([]byte(raw))).Scan(&bindings); err != nil || bindings != 1 {
				t.Fatal("signed request lacks its exact actor/job/key/payload binding", bindings, err)
			}
			before := installReplayCounts(t, s)
			a.AppCatalog = nil
			again := installReplayHTTP(a, "apache-waf", "apache-signed-exact-version", u, in)
			if again.Code != 202 || !strings.Contains(again.Body.String(), accepted.JobID) {
				t.Fatal("read-only original lookup failed after catalogue loss", again.Code, again.Body.String())
			}
			for i, n := range installReplayCounts(t, s) {
				if n != before[i] {
					t.Fatal("original lookup rewrote a queue, request or audit")
				}
			}
		})
	}
}
