package appcatalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type githubCatalogTransport func(*http.Request) (*http.Response, error)

func (f githubCatalogTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func githubCatalogResponse(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func githubCatalogFixture(t *testing.T) (*Client, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{BaseURL: DefaultBaseURL, PublicKey: public}, private
}
func githubCatalogBundle(t *testing.T, key ed25519.PrivateKey, version, generated, digest string) string {
	t.Helper()
	catalog := Catalog{SchemaVersion: 1, GeneratedAt: generated, Apps: []CatalogItem{{ID: "sample-app", Name: "Sample", Category: "deployment", Version: version, Summary: "real application catalog update", Stage: "ready", Risk: "maintained", Provider: "runtime", Target: "sample-runtime", Capabilities: []string{"version"}, PackageURL: DefaultBaseURL + "/dist/apps/sample-app/" + version + "/manifest.json", SHA256: digest}}}
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(catalogBundle{Catalog: string(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		t.Fatal(err)
	}
	return string(bundle)
}
func githubCatalogReference(commit string) string {
	return `{"ref":"refs/heads/main","node_id":"ignored","url":"https://untrusted.invalid/never-follow","object":{"type":"commit","sha":"` + commit + `","url":"http://127.0.0.1/private"}}`
}

func TestOfficialCatalogUsesResolvedImmutableCommitNotStaleMain(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("a", 40)
	bundle := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
	calls := []string{}
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		if r.Header.Get("Cache-Control") != "no-cache" || r.URL.RawQuery != "" {
			t.Fatal("immutable check used timestamp or omitted cache directive")
		}
		switch r.URL.String() {
		case githubCatalogRefURL:
			if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Authorization") != "" {
				t.Fatal("unexpected public metadata authority")
			}
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
			return githubCatalogResponse(r, 200, bundle), nil
		default:
			t.Fatalf("unapproved branch, metadata URL or package read: %s", r.URL)
			return nil, errors.New("unexpected read")
		}
	})}
	cache := t.TempDir()
	catalog, info, err := c.LoadCatalog(context.Background(), cache, 0)
	if err != nil || info.Stale || info.ResolvedCommit != commit || catalog.Apps[0].Version != "1.1.0" || len(calls) != 2 {
		t.Fatal(catalog, info, err, calls)
	}
	if catalog.Apps[0].PackageURL != DefaultBaseURL+"/dist/apps/sample-app/1.1.0/manifest.json" {
		t.Fatal("signed original package URL rewritten")
	}
	before := len(calls)
	cached, cacheInfo, err := c.LoadCatalog(context.Background(), cache, time.Hour)
	if err != nil || cached.Apps[0].Version != "1.1.0" || cacheInfo.Source != "verified-cache" || cacheInfo.CheckedAt != "" || cacheInfo.ResolvedCommit != "" || len(calls) != before {
		t.Fatal("TTL cache falsely claimed new branch lookup", cached, cacheInfo, err)
	}
}

func TestOfficialCatalogInvalidBranchMetadataNeverReadsMain(t *testing.T) {
	commit := strings.Repeat("b", 40)
	valid := githubCatalogReference(commit)
	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"offline", "unavailable", 503}, {"rate-limit", "limited", 429}, {"quota", "limited", 403}, {"missing", "missing", 404}, {"redirect", "", 302},
		{"invalid-json", "{", 200}, {"null", "null", 200}, {"array", "[" + valid + "]", 200}, {"trailing", valid + ` {}`, 200},
		{"wrong-ref", strings.Replace(valid, "refs/heads/main", "refs/heads/main-old", 1), 200},
		{"wrong-type", strings.Replace(valid, `"type":"commit"`, `"type":"tag"`, 1), 200},
		{"unsafe-sha", strings.Replace(valid, commit, "../main", 1), 200}, {"uppercase-sha", strings.Replace(valid, commit, strings.ToUpper(commit), 1), 200},
		{"short-sha", strings.Replace(valid, commit, commit[:39], 1), 200}, {"duplicate-ref", strings.Replace(valid, `"ref":`, `"ref":"refs/heads/other","ref":`, 1), 200},
		{"duplicate-object", strings.Replace(valid, `"object":`, `"object":null,"object":`, 1), 200},
		{"duplicate-sha", strings.Replace(valid, `"sha":`, `"sha":"`+strings.Repeat("c", 40)+`","sha":`, 1), 200},
		{"oversize", strings.Repeat(" ", 16<<10) + valid, 200}, {"deep", `{"ref":"refs/heads/main","extra":` + strings.Repeat("[", 9) + "0" + strings.Repeat("]", 9) + `}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := githubCatalogFixture(t)
			calls := 0
			c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { t.Fatal("supplied redirect callback used"); return nil }, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != githubCatalogRefURL {
					t.Fatal("metadata failure downgraded or redirected", r.URL)
				}
				response := githubCatalogResponse(r, tc.code, tc.body)
				if tc.code == 302 {
					response.Header.Set("Location", "http://127.0.0.1/private")
				}
				return response, nil
			})}
			if _, _, _, err := c.FetchCatalog(context.Background()); err == nil || calls != 1 {
				t.Fatal("invalid metadata accepted or retried main", err, calls)
			}
		})
	}
}

func TestOfficialCatalogLegacyFallbackPinnedToSameCommit(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("d", 40)
	var bundle catalogBundle
	if err := json.Unmarshal([]byte(githubCatalogBundle(t, key, "1.0", "2026-10-10T10:00:00Z", strings.Repeat("2", 64))), &bundle); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		switch r.URL.String() {
		case githubCatalogRefURL:
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
			return githubCatalogResponse(r, 404, "missing"), nil
		case githubCatalogCommitBase + commit + "/dist/catalog-v1.json":
			return githubCatalogResponse(r, 200, bundle.Catalog), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.sig":
			return githubCatalogResponse(r, 200, bundle.Signature), nil
		default:
			t.Fatal("legacy fallback crossed branch/commit", r.URL)
			return nil, errors.New("unexpected")
		}
	})}
	catalog, info, err := c.LoadCatalog(context.Background(), t.TempDir(), 0)
	if err != nil || catalog.Apps[0].Version != "1.0" || info.ResolvedCommit != commit || len(calls) != 4 {
		t.Fatal(catalog, info, err, calls)
	}
}

func TestOfficialCatalogFailuresKeepVerifiedCacheButNotFreshness(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("e", 40)
	current := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("3", 64))
	branchFailure := false
	bundleCode := 200
	bundleBody := current
	calls := []string{}
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		switch r.URL.String() {
		case githubCatalogRefURL:
			if branchFailure {
				return githubCatalogResponse(r, 429, "rate limited"), nil
			}
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
			return githubCatalogResponse(r, bundleCode, bundleBody), nil
		default:
			t.Fatal("failed bundle silently downgraded", r.URL)
			return nil, errors.New("unexpected")
		}
	})}
	cache := t.TempDir()
	if _, _, err := c.LoadCatalog(context.Background(), cache, 0); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cache, "catalog-v1.bundle.json")
	original, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"branch-offline", "bundle-offline", "invalid-signature", "modified-same-version", "rollback"} {
		branchFailure = false
		bundleCode = 200
		bundleBody = current
		switch mode {
		case "branch-offline":
			branchFailure = true
		case "bundle-offline":
			bundleCode = 503
		case "invalid-signature":
			bundleBody = strings.Replace(current, "real application", "fake application", 1)
		case "modified-same-version":
			bundleBody = githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:01:00Z", strings.Repeat("4", 64))
		case "rollback":
			bundleBody = githubCatalogBundle(t, key, "1.0", "2026-10-10T09:00:00Z", strings.Repeat("3", 64))
		}
		catalog, info, err := c.LoadCatalog(context.Background(), cache, 0)
		if err != nil || !info.Stale || info.Source != "verified-cache" || info.CheckedAt == "" || info.Error == "" || info.ResolvedCommit != "" || catalog.Apps[0].Version != "1.1.0" {
			t.Fatal(mode, catalog, info, err)
		}
		kept, err := os.ReadFile(cachePath)
		if err != nil || string(kept) != string(original) {
			t.Fatal(mode, "original verified cache changed", err)
		}
	}
}

func TestOfficialCatalogClosedPathsAndCancellation(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	calls := 0
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, r.Context().Err() })}
	for _, p := range []string{"dist/apps/sample-app/1.0/manifest.json", "../private", "signatures/catalog-v1.bundle.json?extra=1"} {
		if _, err := c.getCatalogAtCommit(context.Background(), strings.Repeat("a", 40), p, 4096); err == nil {
			t.Fatal("arbitrary pinned path allowed", p)
		}
	}
	for _, commit := range []string{"", "../main", strings.Repeat("A", 40), strings.Repeat("a", 40) + " "} {
		if _, err := c.getCatalogAtCommit(context.Background(), commit, "signatures/catalog-v1.bundle.json", 4096); err == nil {
			t.Fatal("unsafe commit allowed", commit)
		}
	}
	if calls != 0 {
		t.Fatal("invalid closed input touched network")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := c.FetchCatalog(ctx); err == nil || calls != 1 {
		t.Fatal("cancelled lookup escaped caller context", err, calls)
	}
}

func TestOfficialCatalogConcurrentCacheRefreshes(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("f", 40)
	bundle := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("5", 64))
	calls := 0
	var mu sync.Mutex
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		if r.URL.String() == githubCatalogRefURL {
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		}
		if r.URL.String() != githubCatalogCommitBase+commit+"/signatures/catalog-v1.bundle.json" {
			t.Fatal("unexpected concurrent path", r.URL)
		}
		return githubCatalogResponse(r, 200, bundle), nil
	})}
	cache := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			catalog, info, err := c.LoadCatalog(context.Background(), cache, 0)
			if err != nil || info.Stale || info.ResolvedCommit != commit || catalog.Apps[0].Version != "1.1.0" {
				t.Error(catalog, info, err)
			}
		}()
	}
	wg.Wait()
	if calls != 12 {
		t.Fatal("unexpected duplicated request count", calls)
	}
	if _, _, err := c.cachedCatalog(cache); err != nil {
		t.Fatal("atomic cache not verifiable", err)
	}
}
