package appcatalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVersionOrderingAndPathValidation(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"1.9", "1.10", -1}, {"1.0", "1.0.0", 0}, {"1.0-compat2", "1.0-compat10", -1}, {"8.4.9", "8.4.25", -1}, {"1.1.0", "1.0-compat1", 1}, {"1.0", "1.0-compat1", 1}, {"1.1.0", "1.1.0", 0}} {
		got, ok := CompareVersions(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Fatalf("%s vs %s: %d %v", tc.a, tc.b, got, ok)
		}
	}
	for _, v := range []string{"../1.0", "1.0/../../bad", "1.0?x=1", "", "v1.0", "1.0+../bad"} {
		if ValidVersion(v) {
			t.Fatal("unsafe version accepted", v)
		}
	}
}

func TestForceRefreshAtomicCacheAndFailedChecks(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	version, generated, digest := "1.0", "2026-10-05T00:00:00Z", strings.Repeat("1", 64)
	failure, invalid := false, false
	requests := 0
	var repository *httptest.Server
	repository = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if r.Header.Get("Cache-Control") != "no-cache" || r.URL.Query().Get("check") == "" {
			t.Error("check did not bypass HTTP caches")
		}
		if failure {
			http.Error(w, "offline", 503)
			return
		}
		if r.URL.Path != "/signatures/catalog-v1.bundle.json" {
			http.NotFound(w, r)
			return
		}
		catalog := Catalog{SchemaVersion: 1, GeneratedAt: generated, Apps: []CatalogItem{{ID: "sample-app", Name: "Sample", Category: "deployment", Version: version, Summary: "real app version check", Stage: "ready", Risk: "maintained", Provider: "runtime", Target: "sample-runtime", ManageRoute: "runtimes", Capabilities: []string{"version"}, PackageURL: repository.URL + "/dist/apps/sample-app/" + version + "/manifest.json", SHA256: digest}}}
		raw, _ := json.Marshal(catalog)
		sig := ed25519.Sign(private, raw)
		if invalid {
			sig[0] ^= 0xff
		}
		json.NewEncoder(w).Encode(catalogBundle{Catalog: string(raw), Signature: base64.StdEncoding.EncodeToString(sig)})
	}))
	defer repository.Close()
	der, _ := x509.MarshalPKIXPublicKey(public)
	client, _ := New(repository.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), repository.Client())
	cache := t.TempDir()
	ctx := context.Background()
	first, info, err := client.LoadCatalog(ctx, cache, time.Hour)
	if err != nil || info.Stale || first.Apps[0].Version != "1.0" {
		t.Fatal(first, info, err)
	}
	mu.Lock()
	version = "1.1.0"
	generated = "2026-10-06T00:00:00Z"
	before := requests
	mu.Unlock()
	old, _, err := client.LoadCatalog(ctx, cache, time.Hour)
	if err != nil || old.Apps[0].Version != "1.0" {
		t.Fatal(old, err)
	}
	mu.Lock()
	if requests != before {
		t.Error("fresh TTL cache still downloaded")
	}
	mu.Unlock()
	latest, info, err := client.LoadCatalog(ctx, cache, 0)
	if err != nil || info.Stale || latest.Apps[0].Version != "1.1.0" || info.CheckedAt == "" {
		t.Fatal(latest, info, err)
	}
	for _, mode := range []string{"invalid", "modified-same-version", "rollback", "offline"} {
		mu.Lock()
		invalid = false
		failure = false
		version = "1.1.0"
		generated = "2026-10-06T00:00:00Z"
		digest = strings.Repeat("1", 64)
		switch mode {
		case "invalid":
			invalid = true
		case "modified-same-version":
			digest = strings.Repeat("2", 64)
		case "rollback":
			version = "1.0"
			generated = "2026-10-05T00:00:00Z"
		case "offline":
			failure = true
		}
		mu.Unlock()
		kept, info, err := client.LoadCatalog(ctx, cache, 0)
		if err != nil || !info.Stale || info.Error == "" || kept.Apps[0].Version != "1.1.0" {
			t.Fatal(mode, kept, info, err)
		}
	}
	mu.Lock()
	failure = false
	invalid = false
	version = "1.2.0"
	generated = "2026-10-06T01:00:00Z"
	mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, info, err := client.LoadCatalog(ctx, cache, 0)
			if err != nil || info.Stale || c.Apps[0].Version != "1.2.0" {
				t.Error(c, info, err)
			}
		}()
	}
	wg.Wait()
	if _, _, err := client.cachedCatalog(cache); err != nil {
		t.Fatal("concurrent refresh corrupted signature/payload pair", err)
	}
}
