package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func memcachedEnvelopeFixture(t *testing.T, base string) (*Client, MemcachedReleaseEnvelope, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := memcachedDigestFixture()
	// Unlike the small requirement-only fixture, a release transfer carries a
	// complete manifest. Do not weaken the production null rejection for tests.
	m.Compatibility = Compatibility{OS: []string{"debian-13", "ubuntu-24.04"}, Architectures: []string{"amd64", "arm64"}}
	m.Health = Health{Probe: "compose", Target: "memcached-cache"}
	m.Uninstall = Uninstall{PreserveData: true, ReferenceCheck: true}
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: base + "/dist/apps/memcached/" + m.Version + "/manifest.json", SHA256: hashRuleFeedFile(manifest)}
	// An old generation timestamp is not an expired user grant. This fixture
	// proves offline release identity only; it does not claim branch freshness.
	raw, err := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T00:00:00Z", Repository: "https://own.invalid/fixture", Apps: []CatalogItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{BaseURL: base, PublicKey: public}, MemcachedReleaseEnvelope{Catalog: raw, Signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))), AppManifest: manifest}, private
}

func requireMemcachedEnvelopePlatform(t *testing.T, a MemcachedReleaseAuthority, err error, digest string) {
	t.Helper()
	if runtime.GOOS == "linux" {
		if err != nil || !a.Matches(MemcachedDigestVersion, digest) || a.CatalogSHA256() == "" {
			t.Fatal("independent compiled Linux authority rejected", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "请先升级面板") || a.Matches(MemcachedDigestVersion, digest) {
		t.Fatal("unsupported OS must fail specifically at the native capability gate", err)
	}
}

func TestMemcachedReleaseEnvelopeOfflineAuthorityAndCompiledTrust(t *testing.T) {
	client, in, _ := memcachedEnvelopeFixture(t, DefaultBaseURL)
	digest := hashRuleFeedFile(in.AppManifest)
	wire, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMemcachedReleaseEnvelope(wire)
	if err != nil || !bytes.Equal(decoded.Catalog, in.Catalog) || !bytes.Equal(decoded.Signature, in.Signature) || !bytes.Equal(decoded.AppManifest, in.AppManifest) {
		t.Fatal("exact signed bytes did not survive closed transfer", err)
	}
	// This unexported helper is the only test seam. Public privileged verification
	// has no key/client/base/available-feature injection, even for tests.
	a, err := verifyMemcachedReleaseEnvelope(context.Background(), client, decoded, MemcachedDigestVersion, digest)
	requireMemcachedEnvelopePlatform(t, a, err, digest)
	if _, err = VerifyMemcachedReleaseEnvelope(context.Background(), decoded, MemcachedDigestVersion, digest); err == nil {
		t.Fatal("test key substituted for the compiled official key")
	}
	if runtime.GOOS == "linux" {
		catalogSHA := a.CatalogSHA256()
		decoded.Catalog[0] ^= 1
		decoded.Signature[0] ^= 1
		decoded.AppManifest[0] ^= 1
		if !a.Matches(MemcachedDigestVersion, digest) || a.CatalogSHA256() != catalogSHA {
			t.Fatal("verified authority retained caller-owned mutable input")
		}
	}
	for _, authority := range []MemcachedReleaseAuthority{{}, a} {
		if authority.Matches("1.6.45-compat1", digest) || authority.Matches(MemcachedDigestVersion, strings.Repeat("0", 64)) {
			t.Fatal("authority widened to another release")
		}
	}
	var forged MemcachedReleaseAuthority
	if json.Unmarshal([]byte(`{"verified":true,"version":"1.6.45-compat2","image":"`+MemcachedDigestImage+`"}`), &forged) != nil || forged.Matches(MemcachedDigestVersion, digest) {
		t.Fatal("deserializable authority")
	}
}

func TestMemcachedReleaseEnvelopeRejectsUnboundAuthority(t *testing.T) {
	client, in, _ := memcachedEnvelopeFixture(t, DefaultBaseURL)
	wire, _ := json.Marshal(in)
	for _, scenario := range []string{"catalog", "manifest", "signature", "wrong-version", "old-version", "alias-version", "wrong-hash", "uppercase-hash", "missing-key", "wrong-key", "wrong-origin", "nil-client", "nil-context", "canceled", "empty-catalog", "large-catalog", "large-manifest", "large-signature"} {
		t.Run(scenario, func(t *testing.T) {
			candidate, err := DecodeMemcachedReleaseEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			recv := &Client{BaseURL: client.BaseURL, PublicKey: append(ed25519.PublicKey(nil), client.PublicKey...)}
			ctx, version, digest := context.Background(), MemcachedDigestVersion, hashRuleFeedFile(in.AppManifest)
			switch scenario {
			case "catalog":
				candidate.Catalog[0] ^= 1
			case "manifest":
				candidate.AppManifest = append(candidate.AppManifest, ' ')
			case "signature":
				candidate.Signature[0] ^= 1
			case "wrong-version":
				version = "1.6.45-compat3"
			case "old-version":
				version = "1.6.45-compat1"
			case "alias-version":
				version = "1.6.45-compat02"
			case "wrong-hash":
				digest = strings.Repeat("0", 64)
			case "uppercase-hash":
				digest = strings.ToUpper(digest)
			case "missing-key":
				recv.PublicKey = nil
			case "wrong-key":
				recv.PublicKey = make([]byte, 32)
			case "wrong-origin":
				recv.BaseURL += "/foreign"
			case "nil-client":
				recv = nil
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "empty-catalog":
				candidate.Catalog = nil
			case "large-catalog":
				candidate.Catalog = make([]byte, maxCatalogBytes+1)
			case "large-manifest":
				candidate.AppManifest = make([]byte, maxManifestBytes+1)
			case "large-signature":
				candidate.Signature = make([]byte, 4097)
			}
			if _, err = verifyMemcachedReleaseEnvelope(ctx, recv, candidate, version, digest); err == nil {
				t.Fatal("invalid signed release transfer accepted", scenario)
			}
		})
	}
}

func TestMemcachedReleaseEnvelopeRejectsAmbiguousWire(t *testing.T) {
	_, in, _ := memcachedEnvelopeFixture(t, DefaultBaseURL)
	wire, _ := json.Marshal(in)
	for _, scenario := range []string{"duplicate", "escaped-duplicate", "case-duplicate", "alias-only", "extra-key", "missing", "null", "array", "number-array", "top-array", "trailing", "invalid-base64", "base64-newline", "noncanonical-base64", "empty", "over-budget", "member-over-budget", "invalid-utf8"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), wire...)
			switch scenario {
			case "duplicate":
				raw = append([]byte(`{"catalog":"YQ==",`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"cata\u006cog":"YQ==",`), raw[1:]...)
			case "case-duplicate":
				raw = append([]byte(`{"Catalog":"YQ==",`), raw[1:]...)
			case "alias-only":
				raw = bytes.Replace(raw, []byte(`"catalog":`), []byte(`"CATALOG":`), 1)
			case "extra-key":
				raw = append([]byte(`{"verified":true,`), raw[1:]...)
			case "missing":
				raw = []byte(`{"catalog":"YQ==","signature":"YQ=="}`)
			case "null":
				raw = []byte(`{"catalog":null,"signature":"YQ==","app_manifest":"YQ=="}`)
			case "array", "number-array":
				raw = []byte(`{"catalog":[97],"signature":"YQ==","app_manifest":"YQ=="}`)
			case "top-array":
				raw = append(append([]byte("["), raw...), ']')
			case "trailing":
				raw = append(raw, []byte(" {}")...)
			case "invalid-base64":
				raw = []byte(`{"catalog":"!","signature":"YQ==","app_manifest":"YQ=="}`)
			case "base64-newline":
				raw = []byte(`{"catalog":"YQ==\n","signature":"YQ==","app_manifest":"YQ=="}`)
			case "noncanonical-base64":
				raw = []byte(`{"catalog":"YR==","signature":"YQ==","app_manifest":"YQ=="}`)
			case "empty":
				raw = nil
			case "over-budget":
				raw = bytes.Repeat([]byte(" "), MaxMemcachedReleaseEnvelopeBytes+1)
			case "member-over-budget":
				changed := in
				changed.AppManifest = bytes.Repeat([]byte("x"), maxManifestBytes+1)
				raw, _ = json.Marshal(changed)
			case "invalid-utf8":
				raw = append([]byte(`{"`), 0xff, '"', ':', '1', '}')
			}
			if _, err := DecodeMemcachedReleaseEnvelope(raw); err == nil {
				t.Fatal("ambiguous wire data accepted", scenario)
			}
		})
	}
}

func TestMemcachedReleaseEnvelopeSignedJSONCannotUseParserAmbiguity(t *testing.T) {
	for _, scenario := range []string{"duplicate", "escaped-duplicate", "alias", "nested-duplicate", "nested-alias", "null", "deep", "trailing", "invalid-utf8", "top-array"} {
		for _, member := range []string{"catalog", "manifest"} {
			t.Run(scenario+"/"+member, func(t *testing.T) {
				client, in, private := memcachedEnvelopeFixture(t, DefaultBaseURL)
				raw := in.Catalog
				if member == "manifest" {
					raw = in.AppManifest
				}
				switch scenario {
				case "duplicate":
					raw = append([]byte(`{"schema_version":1,`), raw[1:]...)
				case "escaped-duplicate":
					raw = append([]byte(`{"schema\u005fversion":1,`), raw[1:]...)
				case "alias":
					raw = bytes.Replace(raw, []byte(`"schema_version":`), []byte(`"Schema_Version":`), 1)
				case "nested-duplicate":
					raw = append([]byte(`{"extra":{"id":"one","id":"two"},`), raw[1:]...)
				case "nested-alias":
					raw = append([]byte(`{"extra":{"Id":"one"},`), raw[1:]...)
				case "null":
					raw = append([]byte(`{"extra":null,`), raw[1:]...)
				case "deep":
					raw = []byte(`{"extra":` + strings.Repeat("[", 10) + "1" + strings.Repeat("]", 10) + `}`)
				case "trailing":
					raw = append(raw, []byte(" {}")...)
				case "invalid-utf8":
					raw = append([]byte(`{"extra":"`), 0xff, '"', '}')
				case "top-array":
					raw = append(append([]byte("["), raw...), ']')
				}
				if err := unambiguousMemcachedReleaseJSON(raw); err == nil {
					t.Fatal("ambiguous signed JSON accepted before typed verification")
				}
				if member == "manifest" {
					in.AppManifest = raw
					var catalog Catalog
					if json.Unmarshal(in.Catalog, &catalog) != nil {
						t.Fatal("original fixture invalid")
					}
					catalog.Apps[0].SHA256 = hashRuleFeedFile(raw)
					in.Catalog, _ = json.Marshal(catalog)
				} else {
					in.Catalog = raw
				}
				// Even a valid test-key signature does not excuse JSON ambiguity.
				in.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, in.Catalog)))
				if _, err := verifyMemcachedReleaseEnvelope(context.Background(), client, in, MemcachedDigestVersion, hashRuleFeedFile(in.AppManifest)); err == nil {
					t.Fatal("signed parser ambiguity produced authority")
				}
			})
		}
	}
}

func TestMemcachedReleaseEnvelopeDownloadIsExactBoundedAndUnauthenticated(t *testing.T) {
	var catalogRequests, manifestRequests, unexpected atomic.Int64
	var in MemcachedReleaseEnvelope
	var redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			unexpected.Add(1)
		}
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			catalogRequests.Add(1)
			json.NewEncoder(w).Encode(catalogBundle{Catalog: string(in.Catalog), Signature: string(in.Signature)})
		case "/dist/apps/memcached/" + MemcachedDigestVersion + "/manifest.json":
			manifestRequests.Add(1)
			if redirect.Load() {
				http.Redirect(w, r, "/forbidden", http.StatusFound)
				return
			}
			w.Write(in.AppManifest)
		default:
			unexpected.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, fixture, _ := memcachedEnvelopeFixture(t, server.URL)
	in = fixture
	digest := hashRuleFeedFile(in.AppManifest)
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "panel-session", Value: "must-not-be-forwarded"}})
	client.HTTP = server.Client()
	client.HTTP.Jar = jar
	got, err := client.FetchMemcachedReleaseEnvelope(context.Background(), MemcachedDigestVersion, digest)
	if runtime.GOOS == "linux" {
		if err != nil || !bytes.Equal(got.Catalog, in.Catalog) || !bytes.Equal(got.Signature, in.Signature) || !bytes.Equal(got.AppManifest, in.AppManifest) {
			t.Fatal("download did not retain exact signed bytes", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("unsupported compiled platform downloaded usable authority", err)
	}
	if catalogRequests.Load() != 1 || manifestRequests.Load() != 1 || unexpected.Load() != 0 {
		t.Fatal("closed download made extra requests or leaked cookies")
	}
	if _, err := client.FetchMemcachedReleaseEnvelope(context.Background(), MemcachedDigestVersion, strings.Repeat("0", 64)); err == nil || catalogRequests.Load() != 2 || manifestRequests.Load() != 1 {
		t.Fatal("changed manifest binding fetched a package")
	}
	for _, version := range []string{"1.6.45-compat1", "1.6.45-compat3"} {
		if _, err := client.FetchMemcachedReleaseEnvelope(context.Background(), version, digest); err == nil || catalogRequests.Load() != 2 {
			t.Fatal("unsupported release triggered network access")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.FetchMemcachedReleaseEnvelope(ctx, MemcachedDigestVersion, digest); !errors.Is(err, context.Canceled) || catalogRequests.Load() != 2 {
		t.Fatal("canceled request did not stop before network access", err)
	}
	redirect.Store(true)
	if _, err := client.FetchMemcachedReleaseEnvelope(context.Background(), MemcachedDigestVersion, digest); err == nil || catalogRequests.Load() != 3 || manifestRequests.Load() != 2 || unexpected.Load() != 0 {
		t.Fatal("manifest redirect followed or retried")
	}
}

func TestMemcachedReleaseEnvelopePublishedCompat1CannotAuthorizeDigestUpdate(t *testing.T) {
	raw, err := os.ReadFile("testdata/published-catalog-20261015.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Format       int               `json:"format"`
		SourceCommit string            `json:"source_commit"`
		Catalog      string            `json:"catalog"`
		Signature    string            `json:"signature"`
		Manifests    map[string]string `json:"manifests"`
	}
	if err := strictJSON(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	client := Default()
	catalog, err := client.verifyCatalog([]byte(fixture.Catalog), []byte(fixture.Signature))
	if err != nil {
		t.Fatal("original official signature", err)
	}
	item, found := Find(catalog, "memcached")
	if !found || item.Version != "1.6.45-compat1" {
		t.Fatal("original published Memcached identity changed")
	}
	in := MemcachedReleaseEnvelope{Catalog: []byte(fixture.Catalog), Signature: []byte(fixture.Signature), AppManifest: []byte(fixture.Manifests["memcached"])}
	for _, version := range []string{item.Version, MemcachedDigestVersion} {
		if _, err := VerifyMemcachedReleaseEnvelope(context.Background(), in, version, item.SHA256); err == nil {
			t.Fatal("actual old signed package borrowed future digest authority")
		}
	}
}
