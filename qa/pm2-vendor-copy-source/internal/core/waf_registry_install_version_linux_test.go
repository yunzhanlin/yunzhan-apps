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
	"local/panel/internal/geodata"
	"local/panel/internal/runtimecatalog"
)

// A real signature/manifest/Core HTTP contract with a temporary fixture key.
// It is not a live original-key application installation or Root engine proof.
func TestWAFRegistrySignedInstallBindsExactImplementationAndOriginalReplay(t *testing.T) {
	for _, version := range []string{"2.5.1", "2.5.2", "2.6.0"} {
		t.Run(version, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "waf-signed-admin", "admin", nil)
			m := appcatalog.Manifest{SchemaVersion: 1, ID: "nginx-waf", Name: "Nginx WAF", Category: "professional", Version: version, Summary: "Private exact signed WAF installation contract", Stage: "ready", Risk: "normal", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "nginx-waf", ManageRoute: "security"}, Compatibility: appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}}, Capabilities: []string{"install"}}
			if version == "2.5.2" {
				m.RequiredPanelFeatures = []string{appcatalog.WAFBoundHealthFeature}
			}
			if version == "2.6.0" {
				m.RequiredPanelFeatures = []string{appcatalog.CountryDataFeature}
				m.CountryDataChannel = &appcatalog.GeoDataChannel{ID: geodata.CountryChannel, Format: 1}
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
				case "/dist/apps/nginx-waf/" + version + "/manifest.json":
					w.Write(manifest)
				default:
					http.NotFound(w, r)
				}
			}))
			defer host.Close()
			item = appcatalog.CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: host.URL + "/dist/apps/nginx-waf/" + version + "/manifest.json", SHA256: Hash(string(manifest))}
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
			result := installReplayHTTP(a, "nginx-waf", "signed-waf-exact-version", u, in)
			var count int
			if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if version != WAFVersion {
				if result.Code != 409 || count != 0 || !strings.Contains(result.Body.String(), "未排队") {
					t.Fatal("stale signed catalog silently enabled a newer implementation", result.Code, count, result.Body.String())
				}
				return
			}
			var accepted struct {
				JobID string `json:"job_id"`
			}
			if result.Code != 202 || json.Unmarshal(result.Body.Bytes(), &accepted) != nil || !ValidID(accepted.JobID) || count != 1 {
				t.Fatal("current signed version did not enqueue one original install", result.Code, count, result.Body.String())
			}
			var raw, target, kind string
			if err := s.DB.QueryRow(`SELECT payload,target_id,kind FROM runtime_jobs WHERE id=?`, accepted.JobID).Scan(&raw, &target, &kind); err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Version  string         `json:"version"`
				Settings map[string]any `json:"settings"`
			}
			if json.Unmarshal([]byte(raw), &payload) != nil || payload.Version != version || target != "nginx-waf" || kind != "software_install" || payload.Settings == nil {
				t.Fatal("verified package version was dropped before privileged dispatch", raw, target, kind)
			}
			original, err := s.readWAFApplyOriginal("nginx-waf", u.ID, accepted.JobID)
			if err != nil || !original.ReadOnly || !original.Request.SignedInstall || original.Request.PayloadSHA != registryInstallDigest([]byte(raw)) {
				t.Fatal("versioned signed original cannot be read without a replacement write", err)
			}
			request, err := softwareExecutorPayload("nginx-waf", accepted.JobID, payload.Settings, payload.Version)
			if err != nil || request["version"] != version {
				t.Fatal("privileged dispatcher dropped signed package version", err)
			}
			before := installReplayCounts(t, s)
			a.AppCatalog = nil
			again := installReplayHTTP(a, "nginx-waf", "signed-waf-exact-version", u, in)
			if again.Code != 202 || !strings.Contains(again.Body.String(), accepted.JobID) {
				t.Fatal("original signed install identity could not be observed after catalog loss", again.Code)
			}
			for i, n := range installReplayCounts(t, s) {
				if n != before[i] {
					t.Fatal("exact replay changed original queue/bindings")
				}
			}
		})
	}
}
