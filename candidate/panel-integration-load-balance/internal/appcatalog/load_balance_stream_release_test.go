package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamReleaseFixture(t *testing.T, base string, change func(*Manifest)) (*Client, LoadBalanceStreamReleaseEnvelope) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{SchemaVersion: 1, ID: "load-balance", Name: "isolated stream crypto fixture", Category: "professional", Version: loadbalancestream.AppVersion, Summary: "Fixture, not a published or installed application", Stage: "ready", Risk: "privileged",
		Delivery: Delivery{Provider: "panel-module", Target: "load-balance", ManageRoute: "app-modules"}, Compatibility: Compatibility{OS: []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"}, Architectures: []string{"amd64", "arm64"}}, Capabilities: []string{"isolated fixture"}, Health: Health{Probe: "panel-api", Target: "/api/app-modules/load-balance"}, Uninstall: Uninstall{PreserveData: true, ReferenceCheck: true}, RequiredPanelFeatures: []string{LoadBalanceStreamFeature}}
	if change != nil {
		change(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: base + "/dist/apps/" + m.ID + "/" + m.Version + "/manifest.json", SHA256: hashRuleFeedFile(raw)}
	catalog, err := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-25T00:00:00Z", Repository: "https://isolated.invalid/fixture", Apps: []CatalogItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{BaseURL: base, PublicKey: public}, LoadBalanceStreamReleaseEnvelope{Catalog: catalog, Signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalog))), AppManifest: raw}
}

func streamReleaseFixtureAvailable(f string) bool { return f == LoadBalanceStreamFeature }

func TestLoadBalanceStreamEnvelopeDistinctOfflineImmutableAndNotCompiledAvailable(t *testing.T) {
	client, in := streamReleaseFixture(t, DefaultBaseURL, nil)
	digest := hashRuleFeedFile(in.AppManifest)
	raw, _ := json.Marshal(in)
	decoded, err := DecodeLoadBalanceStreamReleaseEnvelope(raw)
	if err != nil || !bytes.Equal(decoded.Catalog, in.Catalog) || !bytes.Equal(decoded.Signature, in.Signature) || !bytes.Equal(decoded.AppManifest, in.AppManifest) {
		t.Fatal("closed metadata buffers changed", err)
	}
	a, err := verifyLoadBalanceStreamReleaseEnvelope(context.Background(), client, decoded, loadbalancestream.AppVersion, digest, streamReleaseFixtureAvailable)
	if err != nil || !a.Matches(loadbalancestream.AppVersion, digest) || a.CatalogSHA256() != hashRuleFeedFile(in.Catalog) {
		t.Fatal("independent signed fixture refused", err)
	}
	decoded.Catalog[0] ^= 1
	decoded.Signature[0] ^= 1
	decoded.AppManifest[0] ^= 1
	if !a.Matches(loadbalancestream.AppVersion, digest) {
		t.Fatal("authority retained mutable request buffers")
	}
	for _, v := range []string{"1.8.4", "1.8.5", "1.9.0-compat1", "1.9.1"} {
		if a.Matches(v, digest) {
			t.Fatal("foreign/legacy version inherited native authority", v)
		}
	}
	var forged LoadBalanceStreamReleaseAuthority
	if json.Unmarshal([]byte(`{"verified":true,"version":"1.9.0"}`), &forged) != nil || forged.Matches(loadbalancestream.AppVersion, digest) {
		t.Fatal("JSON forged private authority")
	}
	if got, err := VerifyLoadBalanceStreamReleaseEnvelope(context.Background(), in, loadbalancestream.AppVersion, digest); err == nil || got.Matches(loadbalancestream.AppVersion, digest) {
		t.Fatal("fixture supplied a Root trust key or unavailable handler")
	}
	if OfficialCatalogChannel() != "candidate" && panelFeatureAvailable(LoadBalanceStreamFeature) {
		t.Fatal("unfinished controller was advertised as a compiled stable handler")
	}
}

func TestLoadBalanceStreamEnvelopeCorrectSignatureCannotBorrowLegacyOrForeignContract(t *testing.T) {
	changes := map[string]func(*Manifest){
		"legacy-version": func(m *Manifest) { m.Version = "1.8.5" }, "future-version": func(m *Manifest) { m.Version = "1.9.1" }, "foreign-app": func(m *Manifest) { m.ID = "memcached" },
		"provider": func(m *Manifest) { m.Delivery.Provider = "runtime" }, "target": func(m *Manifest) { m.Delivery.Target = "nginx" }, "route": func(m *Manifest) { m.Delivery.ManageRoute = "docker" }, "image": func(m *Manifest) { m.Delivery.Image = "foreign:latest" }, "isolation": func(m *Manifest) { m.Delivery.Isolation = "other" },
		"feature-missing": func(m *Manifest) { m.RequiredPanelFeatures = nil }, "feature-foreign": func(m *Manifest) { m.RequiredPanelFeatures = []string{MemcachedUnixFeature} }, "feature-duplicate": func(m *Manifest) { m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, LoadBalanceStreamFeature) },
		"health": func(m *Manifest) { m.Health.Target = "/api/software" }, "data-retention": func(m *Manifest) { m.Uninstall.PreserveData = false }, "reference-check": func(m *Manifest) { m.Uninstall.ReferenceCheck = false },
		"os-missing": func(m *Manifest) { m.Compatibility.OS = m.Compatibility.OS[:4] }, "os-duplicate": func(m *Manifest) { m.Compatibility.OS[4] = m.Compatibility.OS[0] }, "arch-duplicate": func(m *Manifest) { m.Compatibility.Architectures[1] = "amd64" },
		"rule-feed": func(m *Manifest) { m.RuleFeeds = []RuleFeed{{}} }, "geodata": func(m *Manifest) { m.GeoDataChannel = &GeoDataChannel{} }, "rule-data": func(m *Manifest) { m.RuleDataChannel = &RuleDataChannel{} },
		"empty-capability": func(m *Manifest) { m.Capabilities = nil }, "stage": func(m *Manifest) { m.Stage = "candidate" }, "risk": func(m *Manifest) { m.Risk = "standard" }, "category": func(m *Manifest) { m.Category = "database" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			client, in := streamReleaseFixture(t, DefaultBaseURL, change)
			digest := hashRuleFeedFile(in.AppManifest)
			if a, err := verifyLoadBalanceStreamReleaseEnvelope(context.Background(), client, in, loadbalancestream.AppVersion, digest, streamReleaseFixtureAvailable); err == nil || a.Matches(loadbalancestream.AppVersion, digest) {
				t.Fatal("valid signature widened the closed independent contract", name)
			}
		})
	}
}

func TestLoadBalanceStreamEnvelopeWireAndPinnedInputsRefuse(t *testing.T) {
	client, in := streamReleaseFixture(t, DefaultBaseURL, nil)
	digest := hashRuleFeedFile(in.AppManifest)
	for _, fault := range []string{"catalog", "signature", "manifest", "key", "digest", "version", "nil-context", "canceled", "unavailable"} {
		t.Run(fault, func(t *testing.T) {
			copy := LoadBalanceStreamReleaseEnvelope{Catalog: bytes.Clone(in.Catalog), Signature: bytes.Clone(in.Signature), AppManifest: bytes.Clone(in.AppManifest)}
			// Start a separate fixture cache/lock instead of copying the
			// original client's sync.Mutex and any in-flight cache state.
			c := Client{BaseURL: client.BaseURL, PublicKey: bytes.Clone(client.PublicKey), HTTP: client.HTTP}
			d, v, ctx, available := digest, loadbalancestream.AppVersion, context.Background(), streamReleaseFixtureAvailable
			switch fault {
			case "catalog":
				copy.Catalog[0] ^= 1
			case "signature":
				copy.Signature[0] ^= 1
			case "manifest":
				copy.AppManifest[0] ^= 1
			case "key":
				c.PublicKey = make([]byte, 32)
			case "digest":
				d = strings.Repeat("0", 64)
			case "version":
				v = "1.8.5"
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unavailable":
				available = func(string) bool { return false }
			}
			if a, err := verifyLoadBalanceStreamReleaseEnvelope(ctx, &c, copy, v, d, available); err == nil || a.Matches(v, d) {
				t.Fatal("unbound bytes/context/key/availability authorized a release", fault)
			}
		})
	}
	for _, raw := range []string{`{}`, `null`, `{"catalog":"YQ==","catalog":"YQ==","signature":"YQ==","app_manifest":"YQ=="}`, `{"catalog":[97],"signature":"YQ==","app_manifest":"YQ=="}`, `{"catalog":"YQ==","signature":null,"app_manifest":"YQ=="}`, `{"catalog":"YQ==","signature":"YQ==","app_manifest":"YQ==","public_key":"YQ=="}`} {
		if _, err := DecodeLoadBalanceStreamReleaseEnvelope([]byte(raw)); err == nil {
			t.Fatal("ambiguous/foreign wire accepted")
		}
	}
}

func TestLoadBalanceStreamEnvelopeClosedDownloadAndUnavailableBeforeNetwork(t *testing.T) {
	var catalogCount, manifestCount, unexpected atomic.Int64
	var in LoadBalanceStreamReleaseEnvelope
	var redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			unexpected.Add(1)
		}
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			catalogCount.Add(1)
			json.NewEncoder(w).Encode(catalogBundle{Catalog: string(in.Catalog), Signature: string(in.Signature)})
		case "/dist/apps/load-balance/1.9.0/manifest.json":
			manifestCount.Add(1)
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
	client, fixture := streamReleaseFixture(t, server.URL, nil)
	in = fixture
	digest := hashRuleFeedFile(in.AppManifest)
	client.HTTP = server.Client()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "panel-session", Value: "private-fixture"}})
	client.HTTP.Jar = jar
	var productionCopies int64
	production, productionErr := client.FetchLoadBalanceStreamReleaseEnvelope(context.Background(), loadbalancestream.AppVersion, digest)
	if LoadBalanceStreamAvailable() {
		productionCopies = 1
		if productionErr != nil || !bytes.Equal(production.Catalog, in.Catalog) || !bytes.Equal(production.AppManifest, in.AppManifest) || !bytes.Equal(production.Signature, in.Signature) {
			t.Fatal("compiled candidate transfer refused exact fixture bytes", productionErr)
		}
	} else if productionErr == nil {
		t.Fatal("unavailable production handler accepted a transfer")
	}
	if catalogCount.Load() != productionCopies || manifestCount.Load() != productionCopies || unexpected.Load() != 0 {
		t.Fatal("production channel did not honor its actual availability or leaked credentials")
	}
	if _, err := client.fetchLoadBalanceStreamReleaseEnvelope(context.Background(), loadbalancestream.AppVersion, digest, func(string) bool { return false }); err == nil || catalogCount.Load() != productionCopies || manifestCount.Load() != productionCopies {
		t.Fatal("unavailable handler performed a network request")
	}
	got, err := client.fetchLoadBalanceStreamReleaseEnvelope(context.Background(), loadbalancestream.AppVersion, digest, streamReleaseFixtureAvailable)
	if err != nil || !bytes.Equal(got.Catalog, in.Catalog) || !bytes.Equal(got.AppManifest, in.AppManifest) || !bytes.Equal(got.Signature, in.Signature) || catalogCount.Load() != productionCopies+1 || manifestCount.Load() != productionCopies+1 || unexpected.Load() != 0 {
		t.Fatal("private fixture transfer changed bytes, leaked credentials or added requests", err)
	}
	redirect.Store(true)
	if _, err := client.fetchLoadBalanceStreamReleaseEnvelope(context.Background(), loadbalancestream.AppVersion, digest, streamReleaseFixtureAvailable); err == nil || unexpected.Load() != 0 || catalogCount.Load() != productionCopies+2 || manifestCount.Load() != productionCopies+2 {
		t.Fatal("redirect was followed or retried")
	}
	if _, err := client.fetchLoadBalanceStreamReleaseEnvelope(context.Background(), "1.8.5", digest, streamReleaseFixtureAvailable); err == nil || catalogCount.Load() != productionCopies+2 {
		t.Fatal("legacy version triggered native package download")
	}
}
