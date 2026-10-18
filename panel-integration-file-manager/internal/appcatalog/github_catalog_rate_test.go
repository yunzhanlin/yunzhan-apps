package appcatalog

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubCatalogRetryHeadersBounded(t *testing.T) {
	now := time.Unix(1791630000, 0).UTC()
	for _, tc := range []struct {
		name    string
		code    int
		headers map[string][]string
		delay   time.Duration
		limited bool
	}{
		{"primary", 403, map[string][]string{"X-RateLimit-Remaining": {"0"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(10 * time.Minute).Unix())}}, 10*time.Minute + time.Second, true},
		{"secondary", 429, map[string][]string{"Retry-After": {"90"}}, 90 * time.Second, true},
		{"longer-primary", 403, map[string][]string{"Retry-After": {"90"}, "X-RateLimit-Remaining": {"0"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(10 * time.Minute).Unix())}}, 10*time.Minute + time.Second, true},
		{"longer-secondary", 403, map[string][]string{"Retry-After": {"900"}, "X-RateLimit-Remaining": {"0"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(10 * time.Minute).Unix())}}, 15 * time.Minute, true},
		{"minimum", 429, map[string][]string{"Retry-After": {"1"}}, time.Minute, true},
		{"missing", 429, nil, time.Minute, true},
		{"forbidden-not-claimed-quota", 403, nil, time.Minute, false},
		{"malformed", 429, map[string][]string{"Retry-After": {"-99"}}, time.Minute, true},
		{"overflow", 429, map[string][]string{"Retry-After": {"99999999999999999999"}}, time.Minute, true},
		{"duplicate", 429, map[string][]string{"Retry-After": {"90", "900"}}, time.Minute, true},
		{"past-reset", 403, map[string][]string{"X-RateLimit-Remaining": {"0"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(-time.Hour).Unix())}}, time.Minute, true},
		{"future-reset-bounded", 403, map[string][]string{"X-RateLimit-Remaining": {"0"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(48 * time.Hour).Unix())}}, time.Minute, true},
		{"nonzero-reset-not-quota", 403, map[string][]string{"X-RateLimit-Remaining": {"2"}, "X-RateLimit-Reset": {fmt.Sprint(now.Add(time.Hour).Unix())}}, time.Minute, false},
		{"date-not-relative-seconds", 429, map[string][]string{"Retry-After": {"Sat, 10 Oct 2026 12:00:00 GMT"}}, time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &http.Response{StatusCode: tc.code, Header: make(http.Header)}
			for name, values := range tc.headers {
				for _, v := range values {
					response.Header.Add(name, v)
				}
			}
			retry := githubCatalogRetry(response, now)
			if !retry.until.Equal(now.Add(tc.delay)) || !retry.checkedAt.Equal(now) || retry.rateLimited != tc.limited {
				t.Fatal(retry)
			}
		})
	}
}
func TestGitHubCatalogRateCacheNeverClaimsFreshOrTouchesNetworkBeforeRetry(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("a", 40)
	bundle := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
	calls := 0
	limited := false
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() == githubCatalogGitRefURL {
			// Both independent official services failed in this fixture.
			// A verified old cache is never presented as a fresh lookup.
			return githubCatalogResponse(r, 503, "never reflect Git service payload"), nil
		}
		if r.URL.String() == githubCatalogRefURL {
			if limited {
				response := githubCatalogResponse(r, 403, "never reflect upstream payload or credential")
				response.Header.Set("X-RateLimit-Remaining", "0")
				response.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(10*time.Minute).Unix()))
				return response, nil
			}
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		}
		if r.URL.String() != githubCatalogCommitBase+commit+"/signatures/catalog-v1.bundle.json" {
			t.Fatal("unapproved request", r.URL)
		}
		return githubCatalogResponse(r, 200, bundle), nil
	})}
	cache := t.TempDir()
	if _, _, err := c.LoadCatalog(context.Background(), cache, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache, "catalog-v1.bundle.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	limited = true
	_, first, err := c.LoadCatalog(context.Background(), cache, 0)
	if err != nil || !first.Stale || first.RetryAt == "" || first.ResolvedCommit != "" || calls != 4 {
		t.Fatal(first, err, calls)
	}
	for i := 0; i < 20; i++ {
		age := time.Duration(0)
		if i%2 == 0 {
			age = time.Hour
		}
		catalog, info, err := c.LoadCatalog(context.Background(), cache, age)
		if err != nil || !info.Stale || info.CheckedAt != first.CheckedAt || info.RetryAt != first.RetryAt || info.ResolvedCommit != "" || catalog.Apps[0].Version != "1.1.0" || calls != 4 || strings.Contains(info.Error, "credential") {
			t.Fatal(info, err, calls)
		}
		preserved, e := os.ReadFile(path)
		if e != nil || string(preserved) != string(original) {
			t.Fatal("signed bytes changed", e)
		}
	}
	// Unit-only simulated deadline expiry; production has no override or retry bypass.
	c.githubRefMu.Lock()
	expired := *c.githubRetry
	expired.until = time.Now().Add(-time.Second)
	c.githubRetry = &expired
	c.githubRefMu.Unlock()
	limited = false
	_, info, err := c.LoadCatalog(context.Background(), cache, 0)
	if err != nil || info.Stale || info.RetryAt != "" || info.ResolvedCommit != commit || calls != 6 || c.githubFailures != 0 || c.githubGitFailures != 0 {
		t.Fatal(info, err, calls)
	}
}
func TestGitHubCatalogSecondaryBackoffIncreasesAndSuccessfulLookupResets(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	calls := 0
	limited := true
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if limited {
			return githubCatalogResponse(r, 429, "limited"), nil
		}
		return githubCatalogResponse(r, 200, githubCatalogReference(strings.Repeat("b", 40))), nil
	})}
	for i := uint(0); i < 8; i++ {
		before := time.Now()
		if _, err := c.resolveCatalogCommit(context.Background()); err == nil {
			t.Fatal("quota accepted")
		}
		delay := time.Minute * time.Duration(1<<min(i, 5))
		if c.githubRetry.until.Before(before.Add(delay)) || c.githubFailures != min(i+1, 6) || calls != int(i)+1 {
			t.Fatal("secondary retry not increasing", c.githubRetry, c.githubFailures, calls)
		}
		if _, err := c.resolveCatalogCommit(context.Background()); err == nil || calls != int(i)+1 {
			t.Fatal("cooldown touched network", err, calls)
		}
		c.githubRefMu.Lock()
		expired := *c.githubRetry
		expired.until = time.Now().Add(-time.Second)
		c.githubRetry = &expired
		c.githubRefMu.Unlock()
	}
	limited = false
	if _, err := c.resolveCatalogCommit(context.Background()); err != nil || c.githubRetry != nil || c.githubFailures != 0 {
		t.Fatal(err, c.githubRetry, c.githubFailures)
	}
}
func TestGitHubCatalogConcurrentQuotaDoesNotBurstOrReadMutableMain(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	var calls atomic.Int32
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != githubCatalogRefURL {
			t.Error("quota downgraded", r.URL)
		}
		return githubCatalogResponse(r, 429, "limited"), nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, err := c.FetchCatalog(context.Background()); err == nil {
				t.Error("quota accepted")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent checks burst during quota", calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := c.FetchCatalog(ctx); err != context.Canceled || calls.Load() != 1 {
		t.Fatal("cancelled check touched network", err, calls.Load())
	}
}
func TestGitHubCatalogRetryDoesNotInventMetadataForCustomSource(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	c.BaseURL = "https://custom.invalid/apps"
	calls := 0
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "custom.invalid" {
			t.Fatal("guessed GitHub or redirected", r.URL)
		}
		return githubCatalogResponse(r, 403, "custom forbidden"), nil
	})}
	for i := 0; i < 3; i++ {
		if _, _, _, err := c.FetchCatalog(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 403") || c.githubRetry != nil {
			t.Fatal(err, c.githubRetry)
		}
	}
	if calls != 3 {
		t.Fatal("custom protocol silently changed", calls)
	}
}
