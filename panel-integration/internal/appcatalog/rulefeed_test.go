package appcatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"local/panel/internal/rulefeed"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ruleFeedFixture(t *testing.T) (Manifest, *rulefeed.Bundle) {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, name := range []string{"LICENSE", "BSD-License.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "rulefeed", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		writer.WriteHeader(&tar.Header{Name: "rules/" + name, Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(data))})
		writer.Write(data)
	}
	text := []byte("alert http any any -> $HOME_NET any (msg:\"own signed repository fixture\";sid:2000001;rev:1;)\n")
	writer.WriteHeader(&tar.Header{Name: "rules/emerging-fixture.rules", Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(text))})
	writer.Write(text)
	writer.Close()
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	zip.Write(raw.Bytes())
	zip.Close()
	source, err := rulefeed.ReadETOpen(context.Background(), bytes.NewReader(compressed.Bytes()), hashRuleFeedFile(compressed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := rulefeed.Build(source, rulefeed.Profile{Categories: []string{"emerging-fixture"}, Variables: []string{"HOME_NET"}, MaxEnabled: 128})
	if err != nil {
		t.Fatal(err)
	}
	feed := RuleFeed{ID: "et-open-web-20261009", ManifestSHA256: hashRuleFeedFile(bundle.Files["manifest.json"])}
	names := []string{}
	for name := range bundle.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		feed.Assets = append(feed.Assets, RuleFeedAsset{Name: name, SHA256: hashRuleFeedFile(bundle.Files[name]), Bytes: len(bundle.Files[name])})
	}
	manifest := Manifest{SchemaVersion: 1, ID: "network-threat-detection", Name: "Network threat detection", Category: "professional", Version: "1.3.0", Summary: "own test fixture", Stage: "ready", Risk: "maintained", Delivery: Delivery{Provider: "panel-module", Target: "network-threat-detection", ManageRoute: "software"}, Compatibility: Compatibility{OS: []string{"debian-13"}, Architectures: []string{"amd64", "arm64"}}, Capabilities: []string{"passive IDS"}, Health: Health{Probe: "module"}, Uninstall: Uninstall{PreserveData: true, ReferenceCheck: true}, RuleFeeds: []RuleFeed{feed}}
	return manifest, bundle
}

func feedRepository(t *testing.T, manifest Manifest, bundle *rulefeed.Bundle, tamper string) (*Client, *httptest.Server, *atomic.Int64) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requests := &atomic.Int64{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestPath := "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/manifest.json"
		if r.URL.Path == "/signatures/catalog-v1.bundle.json" {
			item := CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: manifest.Stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: server.URL + manifestPath, SHA256: hashRuleFeedFile(manifestRaw)}
			catalog := Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T00:00:00Z", Repository: "https://own.invalid", Apps: []CatalogItem{item}}
			raw, _ := json.Marshal(catalog)
			data, _ := json.Marshal(catalogBundle{Catalog: string(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))})
			w.Write(data)
			return
		}
		if r.URL.Path == manifestPath {
			w.Write(manifestRaw)
			return
		}
		prefix := "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/rules/" + manifest.RuleFeeds[0].ID + "/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			name := strings.TrimPrefix(r.URL.Path, prefix)
			data, ok := bundle.Files[name]
			if ok {
				requests.Add(1)
				if name == tamper {
					data = append([]byte(nil), data...)
					data[0] ^= 1
				}
				w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	}))
	der, _ := x509.MarshalPKIXPublicKey(public)
	client, err := New(server.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), server.Client())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server, requests
}

func TestSignedManifestRuleFeedDownloadsOnlyExplicitClosedDataset(t *testing.T) {
	manifest, bundle := ruleFeedFixture(t)
	client, server, requests := feedRepository(t, manifest, bundle, "")
	defer server.Close()
	catalog, _, err := client.LoadCatalog(context.Background(), t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.FetchManifest(context.Background(), catalog.Apps[0], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("manifest pull downloaded rule assets implicitly")
	}
	if _, err := client.FetchRuleFeed(context.Background(), verified, "unlisted-feed"); err == nil || requests.Load() != 0 {
		t.Fatal("unlisted dataset triggered download")
	}
	data, err := client.FetchRuleFeed(context.Background(), verified, verified.RuleFeeds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 6 || len(data.Rules) != 1 || data.Manifest.NativeSyntaxVerified || data.Manifest.PublisherSignatureVerified || !bytes.Equal(data.Files["et-open.rules"], bundle.Files["et-open.rules"]) {
		t.Fatal("wrong closed delivery or false runtime proof")
	}
}

func TestSignedRuleFeedRejectsTamperedMemberAndUnsafeMetadata(t *testing.T) {
	for _, name := range []string{"manifest.json", "et-open.rules", "LICENSE", "classification.config", "reference.config"} {
		t.Run(name, func(t *testing.T) {
			manifest, bundle := ruleFeedFixture(t)
			client, server, _ := feedRepository(t, manifest, bundle, name)
			defer server.Close()
			catalog, _, err := client.LoadCatalog(context.Background(), t.TempDir(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := client.FetchManifest(context.Background(), catalog.Apps[0], t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.FetchRuleFeed(context.Background(), verified, verified.RuleFeeds[0].ID); err == nil {
				t.Fatal("tampered signed member accepted")
			}
		})
	}
	for _, scenario := range []string{"foreign-app", "foreign-provider", "path", "invalid-date", "duplicate-member", "extra-member", "upper-hash", "oversize", "manifest-binding"} {
		t.Run(scenario, func(t *testing.T) {
			manifest, _ := ruleFeedFixture(t)
			feed := &manifest.RuleFeeds[0]
			switch scenario {
			case "foreign-app":
				manifest.ID = "file-monitor"
			case "foreign-provider":
				manifest.Delivery.Provider = "runtime"
			case "path":
				feed.ID = "../../run"
			case "invalid-date":
				feed.ID = "et-open-web-20260230"
			case "duplicate-member":
				feed.Assets[1] = feed.Assets[0]
			case "extra-member":
				feed.Assets = append(feed.Assets, RuleFeedAsset{Name: "run.sh", SHA256: strings.Repeat("1", 64), Bytes: 12})
			case "upper-hash":
				feed.Assets[0].SHA256 = strings.Repeat("A", 64)
			case "oversize":
				feed.Assets[0].Bytes = 9 << 20
			case "manifest-binding":
				feed.ManifestSHA256 = strings.Repeat("0", 64)
			}
			if err := validateRuleFeeds(manifest); err == nil {
				t.Fatal("unclosed metadata accepted", scenario)
			}
		})
	}
}

func TestRuleFeedTransportRefusesRedirectWithoutChangingSharedClient(t *testing.T) {
	manifest, _ := ruleFeedFixture(t)
	foreignRequests := &atomic.Int64{}
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
		w.Write([]byte("unexpected destination"))
	}))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, foreign.URL, http.StatusFound) }))
	defer origin.Close()
	shared := origin.Client()
	client := &Client{BaseURL: origin.URL, HTTP: shared}
	if _, err := client.FetchRuleFeed(context.Background(), manifest, manifest.RuleFeeds[0].ID); err == nil || foreignRequests.Load() != 0 || shared.CheckRedirect != nil {
		t.Fatal("redirect widened scope or shared client changed")
	}
}

func TestRuleFeedIndependentAuthorityRequiresActualSignatureAndPinnedScope(t *testing.T) {
	manifest, bundle := ruleFeedFixture(t)
	client, server, requests := feedRepository(t, manifest, bundle, "")
	defer server.Close()
	raw, err := client.get(context.Background(), client.BaseURL+"/signatures/catalog-v1.bundle.json", 3*maxCatalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	var signed catalogBundle
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := client.get(context.Background(), client.BaseURL+"/dist/apps/"+manifest.ID+"/"+manifest.Version+"/manifest.json", maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashRuleFeedFile(manifestRaw)
	feedID := manifest.RuleFeeds[0].ID
	authority, err := client.VerifyRuleFeedAuthority([]byte(signed.Catalog), []byte(signed.Signature), manifestRaw, manifest.Version, digest, feedID)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("offline authority verification performed a rule download")
	}
	for _, scenario := range []string{"tampered-catalog", "tampered-manifest", "signature", "wrong-version", "wrong-manifest-binding", "unlisted-feed"} {
		t.Run(scenario, func(t *testing.T) {
			catalog := []byte(signed.Catalog)
			signature := []byte(signed.Signature)
			data := append([]byte(nil), manifestRaw...)
			version := manifest.Version
			binding := digest
			feed := feedID
			switch scenario {
			case "tampered-catalog":
				catalog[0] ^= 1
			case "tampered-manifest":
				data[0] ^= 1
			case "signature":
				signature = []byte(strings.Repeat("A", 88))
			case "wrong-version":
				version = "1.2.0"
			case "wrong-manifest-binding":
				binding = strings.Repeat("0", 64)
			case "unlisted-feed":
				feed = "et-open-web-20261008"
			}
			if _, err := client.VerifyRuleFeedAuthority(catalog, signature, data, version, binding, feed); err == nil {
				t.Fatal("unsigned or wrong-scope authority accepted", scenario)
			}
		})
	}
	if _, err := client.FetchVerifiedRuleFeed(context.Background(), RuleFeedAuthority{}); err == nil || requests.Load() != 0 {
		t.Fatal("empty/deserialized authority accepted")
	}
	foreign := &Client{BaseURL: client.BaseURL + "/foreign", PublicKey: client.PublicKey, HTTP: client.HTTP}
	if _, err := foreign.FetchVerifiedRuleFeed(context.Background(), authority); err == nil || requests.Load() != 0 {
		t.Fatal("authority reused across origins")
	}
	wrongKey := &Client{BaseURL: client.BaseURL, PublicKey: make(ed25519.PublicKey, 32), HTTP: client.HTTP}
	if _, err := wrongKey.FetchVerifiedRuleFeed(context.Background(), authority); err == nil || requests.Load() != 0 {
		t.Fatal("authority reused across trust keys")
	}
	data, err := client.FetchVerifiedRuleFeed(context.Background(), authority)
	if err != nil || len(data.Rules) != 1 || requests.Load() != 6 {
		t.Fatal("independently verified closed delivery failed", err)
	}
}
