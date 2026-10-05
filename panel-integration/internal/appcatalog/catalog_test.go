package appcatalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testRepository(t *testing.T, stage string) (*Client, CatalogItem, *httptest.Server) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		SchemaVersion: 1, ID: "sample-app", Name: "Sample App", Category: "deployment", Version: "1.0", Summary: "sample application package", Stage: stage, Risk: "maintained",
		Delivery:      Delivery{Provider: "runtime", Target: "sample-runtime", ManageRoute: "runtimes"},
		Compatibility: Compatibility{OS: []string{"debian-12"}, Architectures: []string{"amd64"}},
		Capabilities:  []string{"sample capability"}, Health: Health{Probe: "binary", Target: "sample --version"}, Uninstall: Uninstall{PreserveData: true, ReferenceCheck: true},
	}
	manifestRaw, _ := json.MarshalIndent(manifest, "", "  ")
	manifestRaw = append(manifestRaw, '\n')
	digest := sha256.Sum256(manifestRaw)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/catalog-v1.json":
			item := CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: server.URL + "/dist/apps/sample-app/1.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
			catalog := Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-05T00:00:00Z", Repository: "https://example.invalid", Apps: []CatalogItem{item}}
			raw, _ := json.MarshalIndent(catalog, "", "  ")
			raw = append(raw, '\n')
			w.Write(raw)
		case "/signatures/catalog-v1.sig":
			item := CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: server.URL + "/dist/apps/sample-app/1.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
			catalog := Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-05T00:00:00Z", Repository: "https://example.invalid", Apps: []CatalogItem{item}}
			raw, _ := json.MarshalIndent(catalog, "", "  ")
			raw = append(raw, '\n')
			w.Write([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))))
		case "/dist/apps/sample-app/1.0/manifest.json":
			w.Write(manifestRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	der, _ := x509.MarshalPKIXPublicKey(public)
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	client, err := New(server.URL, key, server.Client())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	item := CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: server.URL + "/dist/apps/sample-app/1.0/manifest.json", SHA256: hex.EncodeToString(digest[:])}
	return client, item, server
}

func TestSignedCatalogAndManifest(t *testing.T) {
	client, _, server := testRepository(t, "ready")
	defer server.Close()
	cache := t.TempDir()
	catalog, info, err := client.LoadCatalog(context.Background(), cache, time.Hour)
	if err != nil || info.Source != "github" || len(catalog.Apps) != 1 {
		t.Fatal(catalog, info, err)
	}
	manifest, err := client.FetchManifest(context.Background(), catalog.Apps[0], filepath.Join(cache, "packages"))
	if err != nil || manifest.Delivery.Target != "sample-runtime" {
		t.Fatal(manifest, err)
	}
	if _, err = os.Stat(filepath.Join(cache, "packages", "sample-app", "1.0", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	server.Close()
	catalog, info, err = client.LoadCatalog(context.Background(), cache, -time.Second)
	if err != nil || !info.Stale || len(catalog.Apps) != 1 {
		t.Fatal(catalog, info, err)
	}
}

func TestUnsignedCatalogAndUnreadyManifestAreRejected(t *testing.T) {
	client, item, server := testRepository(t, "design")
	defer server.Close()
	if _, err := client.FetchManifest(context.Background(), item, t.TempDir()); err == nil {
		t.Fatal("design-stage application was accepted")
	}
	client.PublicKey[0] ^= 0xff
	if _, _, _, err := client.FetchCatalog(context.Background()); err == nil {
		t.Fatal("invalid catalog signature was accepted")
	}
}
