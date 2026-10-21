package appcatalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func gitCatalogPacket(value string) string { return fmt.Sprintf("%04x", len(value)+4) + value }
func gitCatalogAdvertisement(commit string) string {
	return gitCatalogPacket("# service=git-upload-pack\n") + "0000" +
		gitCatalogPacket(commit+" HEAD\x00multi_ack symref=HEAD:refs/heads/main agent=git/2.51\n") +
		gitCatalogPacket(commit+" refs/heads/main\n") + "0000"
}
func gitCatalogResponse(r *http.Request, code int, body string) *http.Response {
	response := githubCatalogResponse(r, code, body)
	response.Header.Set("Content-Type", "application/x-git-upload-pack-advertisement")
	return response
}
func primaryQuotaResponse(r *http.Request) *http.Response {
	response := githubCatalogResponse(r, 403, "never expose private upstream contents")
	response.Header.Set("X-RateLimit-Remaining", "0")
	response.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(20*time.Minute).Unix()))
	return response
}

func TestGitCatalogAdvertisementCompleteFixedBranchIdentity(t *testing.T) {
	commit := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	raw := gitCatalogPacket("# service=git-upload-pack\n") + "0000" +
		gitCatalogPacket(other+" HEAD\x00symref=HEAD:refs/heads/other\n") +
		gitCatalogPacket(other+" refs/heads/main-old\n") +
		gitCatalogPacket(other+" refs/tags/main\n") +
		gitCatalogPacket(other+" refs/tags/v1^{}\n") +
		gitCatalogPacket(other+" refs/heads/中文分支\n") +
		gitCatalogPacket(commit+" refs/heads/main\n") + "0000"
	actual, err := parseGitCatalogAdvertisement([]byte(raw))
	if err != nil || actual != commit {
		t.Fatal("HEAD/tag/prefix substituted fixed main", actual, err)
	}
}

func TestGitCatalogAdvertisementRejectsAmbiguousAndIncompleteProtocol(t *testing.T) {
	commit := strings.Repeat("a", 40)
	valid := gitCatalogAdvertisement(commit)
	preamble := gitCatalogPacket("# service=git-upload-pack\n") + "0000"
	first := gitCatalogPacket(commit + " HEAD\x00multi_ack\n")
	main := gitCatalogPacket(commit + " refs/heads/main\n")
	cases := map[string]string{
		"empty": "", "html": "<html>sign in</html>", "json": githubCatalogReference(commit),
		"wrong-service":          strings.Replace(valid, "git-upload-pack", "git-receive-pac", 1),
		"uppercase-packet":       strings.Replace(valid, "001e", "001E", 1),
		"missing-preamble-flush": gitCatalogPacket("# service=git-upload-pack\n") + first + main + "0000",
		"preamble-control":       "0001" + valid, "delimiter": preamble + "0001", "response-end": preamble + "0002",
		"invalid-short-packet": preamble + "0003", "truncated-header": preamble + "000",
		"truncated-payload": valid[:len(valid)-6], "missing-final-flush": strings.TrimSuffix(valid, "0000"),
		"trailing": valid + "private extra bytes", "extra-flush": valid + "0000",
		"empty-table": preamble + "0000", "version-v2": preamble + gitCatalogPacket("version 2\n") + "0000",
		"missing-caps":    preamble + gitCatalogPacket(commit+" HEAD\n") + main + "0000",
		"caps-on-second":  preamble + first + gitCatalogPacket(commit+" refs/heads/main\x00multi_ack\n") + "0000",
		"double-nul":      preamble + gitCatalogPacket(commit+" HEAD\x00multi_ack\x00more\n") + main + "0000",
		"cap-control":     preamble + gitCatalogPacket(commit+" HEAD\x00multi_ack\r\n") + main + "0000",
		"duplicate-main":  preamble + first + main + main + "0000",
		"duplicate-head":  preamble + first + gitCatalogPacket(commit+" HEAD\n") + main + "0000",
		"uppercase-sha":   strings.ReplaceAll(valid, commit, strings.ToUpper(commit)),
		"short-sha":       strings.ReplaceAll(valid, commit, commit[:39]),
		"null-sha":        strings.ReplaceAll(valid, commit, strings.Repeat("0", 40)),
		"missing-main":    strings.Replace(valid, "refs/heads/main\n", "refs/heads/main-other\n", 1),
		"extra-field":     preamble + first + gitCatalogPacket(commit+" refs/heads/main extra\n") + "0000",
		"tab":             preamble + first + gitCatalogPacket(commit+"\trefs/heads/main\n") + "0000",
		"double-newline":  preamble + first + gitCatalogPacket(commit+" refs/heads/main\n\n") + "0000",
		"invalid-utf8":    preamble + first + gitCatalogPacket(commit+" refs/heads/\xff\n") + main + "0000",
		"ref-control":     preamble + first + gitCatalogPacket(commit+" refs/heads/x\u0085\n") + main + "0000",
		"ref-traversal":   preamble + first + gitCatalogPacket(commit+" refs/heads/../main\n") + "0000",
		"peeled-head":     preamble + first + gitCatalogPacket(commit+" refs/heads/main^{}\n") + "0000",
		"ref-lock":        preamble + first + gitCatalogPacket(commit+" refs/heads/x.lock\n") + main + "0000",
		"cap-url-no-main": preamble + gitCatalogPacket(commit+" HEAD\x00symref=HEAD:http://127.0.0.1/private\n") + "0000",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseGitCatalogAdvertisement([]byte(raw)); err == nil || got != "" {
				t.Fatal("incomplete protocol accepted", got, err)
			}
		})
	}
}

func TestGitCatalogAdvertisementAllBudgetsApplyBeforeIdentity(t *testing.T) {
	commit := strings.Repeat("c", 40)
	preamble := gitCatalogPacket("# service=git-upload-pack\n") + "0000"
	first := gitCatalogPacket(commit + " HEAD\x00multi_ack\n")
	tooMany := preamble + first + gitCatalogPacket(commit+" refs/heads/main\n")
	for i := 0; i < 511; i++ {
		tooMany += gitCatalogPacket(commit + fmt.Sprintf(" refs/heads/x-%d\n", i))
	}
	for name, raw := range map[string]string{
		"whole-response": strings.Repeat("0", githubGitAdvertisementLimit+1),
		"packet":         preamble + gitCatalogPacket(commit+" HEAD\x00"+strings.Repeat("a", githubGitAdvertisementPacketLimit)+"\n") + "0000",
		"ref-count":      tooMany + "0000",
		"ref-name":       preamble + first + gitCatalogPacket(commit+" refs/heads/"+strings.Repeat("a", 1024)+"\n") + "0000",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseGitCatalogAdvertisement([]byte(raw)); err == nil || got != "" {
				t.Fatal("budget accepted", got, err)
			}
		})
	}
}

func TestGitCatalogPrimaryQuotaUsesOfficialImmutableSignedProtocol(t *testing.T) {
	c, key := githubCatalogFixture(t)
	commit := strings.Repeat("d", 40)
	bundle := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
	calls := []string{}
	jar, _ := cookiejar.New(nil)
	official, _ := url.Parse("https://github.com/")
	jar.SetCookies(official, []*http.Cookie{{Name: "private_cookie", Value: "must-not-travel"}})
	c.HTTP = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { t.Fatal("redirect invoked"); return nil }, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("inherited credential", r.URL)
		}
		switch r.URL.String() {
		case githubCatalogRefURL:
			return primaryQuotaResponse(r), nil
		case githubCatalogGitRefURL:
			if r.Method != "GET" || r.URL.RawQuery != "service=git-upload-pack" || r.Header.Get("Git-Protocol") != "" || r.Header.Get("Cache-Control") != "no-cache" || r.Header.Get("Accept") != "application/x-git-upload-pack-advertisement" {
				t.Fatal("protocol widened", r)
			}
			return gitCatalogResponse(r, 200, gitCatalogAdvertisement(commit)), nil
		case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
			return githubCatalogResponse(r, 200, bundle), nil
		default:
			t.Fatal("unapproved URL", r.URL)
			return nil, errors.New("unexpected")
		}
	})}
	cache := t.TempDir()
	actual, info, err := c.LoadCatalog(context.Background(), cache, 0)
	if err != nil || info.Stale || info.ResolvedCommit != commit || info.ReferenceTransport != "github-smart-http" || info.RetryAt != "" || actual.Apps[0].Version != "1.1.0" || len(calls) != 3 {
		t.Fatal(actual, info, err, calls)
	}
	if c.githubRetry == nil || !c.githubRetry.primaryQuota || c.githubGitRetry != nil {
		t.Fatal("REST cooldown lost", c.githubRetry, c.githubGitRetry)
	}
	if _, _, err = c.LoadCatalog(context.Background(), cache, 0); err != nil || len(calls) != 5 {
		t.Fatal("REST primary cooldown touched API", err, calls)
	}
	if calls[3] != githubCatalogGitRefURL {
		t.Fatal("API retried during explicit quota", calls)
	}
	if actual.Apps[0].PackageURL != DefaultBaseURL+"/dist/apps/sample-app/1.1.0/manifest.json" {
		t.Fatal("signed package URL rewritten")
	}
}

func TestGitCatalogFallbackNeverActivatesForAccessOrSecondaryRefusal(t *testing.T) {
	for _, name := range []string{"plain-forbidden", "secondary-429", "secondary-retry-after", "missing-reset", "past-reset", "distant-reset", "duplicate-reset", "duplicate-remaining", "nonzero-remaining"} {
		t.Run(name, func(t *testing.T) {
			c, _ := githubCatalogFixture(t)
			calls := 0
			c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != githubCatalogRefURL {
					t.Fatal("access refusal widened to Git", r.URL)
				}
				response := primaryQuotaResponse(r)
				switch name {
				case "plain-forbidden":
					response.Header = make(http.Header)
				case "secondary-429":
					response.StatusCode = 429
				case "secondary-retry-after":
					response.Header.Set("Retry-After", "90")
				case "missing-reset":
					response.Header.Del("X-RateLimit-Reset")
				case "past-reset":
					response.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(-time.Hour).Unix()))
				case "distant-reset":
					response.Header.Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(48*time.Hour).Unix()))
				case "duplicate-reset":
					response.Header.Add("X-RateLimit-Reset", "1")
				case "duplicate-remaining":
					response.Header.Add("X-RateLimit-Remaining", "0")
				case "nonzero-remaining":
					response.Header.Set("X-RateLimit-Remaining", "1")
				}
				return response, nil
			})}
			for i := 0; i < 3; i++ {
				if _, _, _, err := c.FetchCatalog(context.Background()); err == nil {
					t.Fatal("denied request accepted")
				}
			}
			if calls != 1 {
				t.Fatal("cooldown burst", calls)
			}
		})
	}
}

func TestGitCatalogResponseFailuresNeverDowngradeOrReflectPayload(t *testing.T) {
	commit := strings.Repeat("e", 40)
	for _, name := range []string{"unavailable", "redirect", "missing-type", "plain-type", "duplicate-type", "malformed-packets", "oversize", "transport-error", "secondary-quota"} {
		t.Run(name, func(t *testing.T) {
			c, _ := githubCatalogFixture(t)
			api, git := 0, 0
			c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { t.Fatal("followed redirect"); return nil }, Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case githubCatalogRefURL:
					api++
					return primaryQuotaResponse(r), nil
				case githubCatalogGitRefURL:
					git++
					response := gitCatalogResponse(r, 200, gitCatalogAdvertisement(commit))
					switch name {
					case "unavailable":
						response = gitCatalogResponse(r, 503, "credential-private")
					case "redirect":
						response.StatusCode = 302
						response.Header.Set("Location", "http://127.0.0.1/private")
					case "missing-type":
						response.Header.Del("Content-Type")
					case "plain-type":
						response.Header.Set("Content-Type", "text/plain")
					case "duplicate-type":
						response.Header.Add("Content-Type", "application/x-git-upload-pack-advertisement")
					case "malformed-packets":
						response = gitCatalogResponse(r, 200, "credential-private")
					case "oversize":
						response = gitCatalogResponse(r, 200, strings.Repeat("x", githubGitAdvertisementLimit+1))
					case "transport-error":
						return nil, errors.New("transport credential-private")
					case "secondary-quota":
						response = gitCatalogResponse(r, 429, "credential-private")
						response.Header.Set("Retry-After", "900")
					}
					return response, nil
				default:
					t.Fatal("failure read another URL", r.URL)
					return nil, errors.New("unexpected")
				}
			})}
			for i := 0; i < 3; i++ {
				if _, _, _, err := c.FetchCatalog(context.Background()); err == nil || strings.Contains(err.Error(), "credential-private") || strings.Contains(err.Error(), "HTTP 0") {
					t.Fatal("false success or reflected error", err)
				}
			}
			if api != 1 || git != 1 || c.githubGitRetry == nil {
				t.Fatal("independent cooldown burst", api, git, c.githubGitRetry)
			}
			if name == "secondary-quota" && time.Until(c.githubGitRetry.until) < 14*time.Minute {
				t.Fatal("ignored Git Retry-After", c.githubGitRetry)
			}
		})
	}
}

func TestGitCatalogSignatureRollbackAndSameVersionImmutabilityRemainRequired(t *testing.T) {
	for _, mode := range []string{"invalid-signature", "rollback", "same-version-new-digest"} {
		t.Run(mode, func(t *testing.T) {
			c, key := githubCatalogFixture(t)
			commit := strings.Repeat("f", 40)
			original := githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:00:00Z", strings.Repeat("1", 64))
			changed := original
			switch mode {
			case "invalid-signature":
				changed = strings.Replace(original, "real application", "fake application", 1)
			case "rollback":
				changed = githubCatalogBundle(t, key, "1.0", "2026-10-10T09:00:00Z", strings.Repeat("1", 64))
			case "same-version-new-digest":
				changed = githubCatalogBundle(t, key, "1.1.0", "2026-10-10T10:01:00Z", strings.Repeat("2", 64))
			}
			first := true
			c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case githubCatalogRefURL:
					return primaryQuotaResponse(r), nil
				case githubCatalogGitRefURL:
					return gitCatalogResponse(r, 200, gitCatalogAdvertisement(commit)), nil
				case githubCatalogCommitBase + commit + "/signatures/catalog-v1.bundle.json":
					if first {
						first = false
						return githubCatalogResponse(r, 200, original), nil
					}
					return githubCatalogResponse(r, 200, changed), nil
				default:
					t.Fatal("unapproved", r.URL)
					return nil, errors.New("unexpected")
				}
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
			catalog, info, err := c.LoadCatalog(context.Background(), cache, 0)
			if err != nil || !info.Stale || info.ResolvedCommit != "" || info.ReferenceTransport != "" || catalog.Apps[0].Version != "1.1.0" {
				t.Fatal("Git metadata became signature authority", catalog, info, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("original signed bytes replaced", err)
			}
		})
	}
}

func TestGitCatalogCancellationNeverStartsFallback(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != githubCatalogRefURL {
			t.Fatal("cancelled call touched Git")
		}
		cancel()
		return primaryQuotaResponse(r), nil
	})}
	if _, _, _, err := c.FetchCatalog(ctx); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	if _, _, _, err := c.FetchCatalog(ctx); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}

func TestGitCatalogConcurrentFailedFallbackDoesNotBurstEitherService(t *testing.T) {
	c, _ := githubCatalogFixture(t)
	var api, git atomic.Int32
	c.HTTP = &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case githubCatalogRefURL:
			api.Add(1)
			return primaryQuotaResponse(r), nil
		case githubCatalogGitRefURL:
			git.Add(1)
			return gitCatalogResponse(r, 503, "failed"), nil
		default:
			t.Fatal("unapproved", r.URL)
			return nil, errors.New("unexpected")
		}
	})}
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, _, _, err := c.FetchCatalog(context.Background()); err == nil {
				t.Error("failure accepted")
			}
		}()
	}
	group.Wait()
	if api.Load() != 1 || git.Load() != 1 {
		t.Fatal("independent cooldown burst", api.Load(), git.Load())
	}
}
