package appcatalog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type repositoryInterruptedBody struct{ closed bool }

func (b *repositoryInterruptedBody) Read(p []byte) (int, error) {
	return copy(p, []byte("partial")), io.ErrUnexpectedEOF
}
func (b *repositoryInterruptedBody) Close() error { b.closed = true; return nil }

// Synthetic transport and test-only signing key. These prove response/authority
// contracts, not real GitHub availability or original-key installation.
func TestRepositoryPartialReadRetriesOnlySameResolvedSignedCommit(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("a", 40)
	bundle := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
	refs, bundles := 0, 0
	partial := &repositoryInterruptedBody{}
	c.HTTP = &http.Client{Timeout: time.Second, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case githubCatalogRefURL:
			refs++
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
			bundles++
			if r.URL.RawQuery != "" || r.Header.Get("Cache-Control") != "no-cache" {
				t.Fatal("retry changed immutable URL/headers")
			}
			if bundles == 1 {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: partial, ContentLength: int64(len(bundle)), Request: r}, nil
			}
			return githubCatalogResponse(r, 200, bundle), nil
		default:
			t.Fatal("read widened source or downgraded bundle protocol", r.URL)
			return nil, errors.New("unapproved source")
		}
	})}
	catalog, info, err := c.LoadCatalog(context.Background(), t.TempDir(), 0)
	if err != nil || info.Stale || info.ResolvedCommit != commit || len(catalog.Apps) != 1 || catalog.Apps[0].Version != "1.1.0" || refs != 1 || bundles != 2 || !partial.closed {
		t.Fatal("partial failure was not safely recovered", err, info, refs, bundles, partial.closed)
	}
}
func TestRepositoryReadRetryNeverAcceptsPartialBytesAndStopsAfterTwo(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	calls := 0
	closed := []*repositoryInterruptedBody{}
	c.HTTP = &http.Client{Timeout: time.Second, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		b := &repositoryInterruptedBody{}
		closed = append(closed, b)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: b, ContentLength: 100, Request: r}, nil
	})}
	r, _ := http.NewRequestWithContext(context.Background(), "GET", DefaultBaseURL+"/dist/catalog-v1.json", nil)
	raw, err := c.readResponse(r, 100)
	if raw != nil || !errors.Is(err, io.ErrUnexpectedEOF) || calls != 2 || len(closed) != 2 || !closed[0].closed || !closed[1].closed {
		t.Fatal("partial success, unbounded retry or leaked body", string(raw), err, calls)
	}
}
func TestRepositoryReadRetryPreservesNegativeSecurityAndRateBoundaries(t *testing.T) {
	for _, kind := range []string{"403", "429", "404", "redirect", "oversize", "wrong-content-type", "post", "cancelled", "unknown-error"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := githubCatalogFixture(t)
			calls := 0
			ctx := context.Background()
			method := "GET"
			target := githubCatalogRefURL
			if kind == "post" {
				method = "POST"
			}
			if kind == "wrong-content-type" {
				target = githubCatalogGitRefURL
			}
			if kind == "cancelled" {
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			c.HTTP = &http.Client{Timeout: time.Second, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				switch kind {
				case "403":
					return githubCatalogResponse(r, 403, "denied"), nil
				case "429":
					out := githubCatalogResponse(r, 429, "limited")
					out.Header.Set("Retry-After", "90")
					return out, nil
				case "404":
					return githubCatalogResponse(r, 404, "missing"), nil
				case "redirect":
					out := githubCatalogResponse(r, 302, "")
					out.Header.Set("Location", "https://unapproved.invalid/never")
					return out, nil
				case "oversize":
					return githubCatalogResponse(r, 200, strings.Repeat("x", 101)), nil
				case "wrong-content-type":
					out := githubCatalogResponse(r, 200, "packet")
					out.Header.Set("Content-Type", "text/html")
					return out, nil
				case "post":
					return nil, io.ErrUnexpectedEOF
				default:
					return nil, errors.New("not a retryable transport failure")
				}
			})}
			r, _ := http.NewRequestWithContext(ctx, method, target, nil)
			raw, err := c.readResponse(r, 100)
			wantCalls := 1
			if kind == "cancelled" {
				wantCalls = 0
			}
			if err == nil || raw != nil || calls != wantCalls {
				t.Fatal("negative boundary retried or accepted", kind, calls, err)
			}
			if kind == "429" {
				var rate *githubCatalogRetryError
				if !errors.As(err, &rate) || !rate.rateLimited || rate.primaryQuota {
					t.Fatal("quota error changed", err)
				}
			}
		})
	}
}
func TestRepositoryReadRetryDoesNotResetParentOrConfiguredDeadline(t *testing.T) {
	for _, source := range []string{"parent", "client"} {
		t.Run(source, func(t *testing.T) {
			c, _ := githubCatalogFixture(t)
			ctx := context.Background()
			var cancel context.CancelFunc
			clientTimeout := time.Second
			if source == "parent" {
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			} else {
				clientTimeout = 25 * time.Millisecond
			}
			calls := 0
			c.HTTP = &http.Client{Timeout: clientTimeout, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })}
			r, _ := http.NewRequestWithContext(ctx, "GET", githubCatalogRefURL, nil)
			start := time.Now()
			raw, err := c.readResponse(r, 100)
			if err == nil || raw != nil || calls != 1 || time.Since(start) > 250*time.Millisecond {
				t.Fatal("retry reset deadline or issued another request", source, calls, time.Since(start), err)
			}
		})
	}
}
func TestRepositoryReadRetryTamperedCompletedResponseNeverReplacesVerifiedCache(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("b", 40)
	good := githubCatalogBundle(t, key, "1.0.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
	bad := strings.Replace(good, "1.0.0", "9.9.9", 1)
	broken := false
	bundleCalls := 0
	c.HTTP = &http.Client{Timeout: time.Second, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == githubCatalogRefURL {
			return githubCatalogResponse(r, 200, githubCatalogReference(commit)), nil
		}
		if r.URL.String() != githubCatalogCommitBase+commit+"/signatures/catalog-v1.bundle.json" {
			t.Fatal("failed signature used a fallback source", r.URL)
		}
		bundleCalls++
		if !broken {
			return githubCatalogResponse(r, 200, good), nil
		}
		if bundleCalls == 2 {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &repositoryInterruptedBody{}, ContentLength: int64(len(bad)), Request: r}, nil
		}
		return githubCatalogResponse(r, 200, bad), nil
	})}
	cache := t.TempDir()
	if _, _, err := c.LoadCatalog(context.Background(), cache, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache, "catalog-v1.bundle.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	broken = true
	catalog, info, err := c.LoadCatalog(context.Background(), cache, 0)
	after, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !info.Stale || info.ResolvedCommit != "" || info.Error == "" || catalog.Apps[0].Version != "1.0.0" || bundleCalls != 3 || !bytes.Equal(before, after) {
		t.Fatal("completed bad signature became a current update or overwrote verified cache", info, err, bundleCalls)
	}
}
func TestRepositoryReadRetryActualLocalTLSTruncationUsesSameGET(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	calls := 0
	firstURI := ""
	full := "abcdefgh"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/dist/catalog-v1.json" || r.Header.Get("Cache-Control") != "no-cache" {
			t.Error("unexpected local TLS read")
		}
		if calls == 1 {
			firstURI = r.RequestURI
		} else if r.RequestURI != firstURI {
			t.Error("retry regenerated URL/query")
		}
		w.Header().Set("Content-Length", "8")
		if calls == 1 {
			_, _ = io.WriteString(w, full[:3])
		} else {
			_, _ = io.WriteString(w, full)
		}
	}))
	defer server.Close()
	c.BaseURL = server.URL
	c.HTTP = server.Client()
	raw, err := c.get(context.Background(), c.BaseURL+"/dist/catalog-v1.json", 8)
	if err != nil || string(raw) != full || calls != 2 {
		t.Fatal("actual local TLS truncation not recovered", string(raw), err, calls)
	}
}
