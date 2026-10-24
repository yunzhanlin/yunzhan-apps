package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func memcachedUnixEnvelopeFixture(t *testing.T, change func(*Manifest)) (*Client, MemcachedUnixReleaseEnvelope) {
	return memcachedUnixEnvelopeFixtureAt(t, DefaultBaseURL, change)
}

func memcachedUnixEnvelopeFixtureAt(t *testing.T, baseURL string, change func(*Manifest)) (*Client, MemcachedUnixReleaseEnvelope) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := memcachedUnixFixture()
	m.Compatibility = Compatibility{OS: []string{"debian-13", "ubuntu-24.04"}, Architectures: []string{"amd64", "arm64"}}
	m.Health = Health{Probe: "panel-api", Target: "memcached-unix-workspace"}
	m.Uninstall = Uninstall{PreserveData: true, ReferenceCheck: true}
	if change != nil {
		change(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: baseURL + "/dist/apps/memcached/" + m.Version + "/manifest.json", SHA256: hashRuleFeedFile(raw)}
	catalog, err := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T00:00:00Z", Repository: "https://own.invalid/fixture", Apps: []CatalogItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{BaseURL: baseURL, PublicKey: public}, MemcachedUnixReleaseEnvelope{
		Catalog: catalog, Signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalog))), AppManifest: raw,
	}
}

func memcachedUnixEnvelopeFixtureHandlers(feature string) bool {
	// Crypto/capability fixture only. This does NOT enable a production handler.
	return feature == MemcachedDigestFeature || feature == MemcachedUnixFeature
}

func TestMemcachedUnixEnvelopeHasIndependentOfflineImmutableAuthority(t *testing.T) {
	client, in := memcachedUnixEnvelopeFixture(t, nil)
	digest := hashRuleFeedFile(in.AppManifest)
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMemcachedUnixReleaseEnvelope(raw)
	if err != nil || !bytes.Equal(decoded.Catalog, in.Catalog) || !bytes.Equal(decoded.AppManifest, in.AppManifest) || !bytes.Equal(decoded.Signature, in.Signature) {
		t.Fatal("exact signed Unix buffers did not survive the existing closed wire bounds", err)
	}
	a, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), client, decoded, MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers)
	if err != nil || !a.Matches(MemcachedUnixVersion, digest) || a.CatalogSHA256() != hashRuleFeedFile(in.Catalog) {
		t.Fatal("signed independent Unix fixture refused", err)
	}
	decoded.Catalog[0] ^= 1
	decoded.Signature[0] ^= 1
	decoded.AppManifest[0] ^= 1
	if !a.Matches(MemcachedUnixVersion, digest) {
		t.Fatal("authority retained caller-owned mutable buffers")
	}
	for _, version := range []string{"1.6.45-compat1", MemcachedDigestVersion, "1.6.45-compat3", "1.6.45-compat5", "1.6.45-compat04"} {
		if a.Matches(version, digest) {
			t.Fatal("Unix authority widened to another release", version)
		}
	}
	for _, digest := range []string{"", strings.Repeat("0", 64), strings.ToUpper(digest)} {
		if a.Matches(MemcachedUnixVersion, digest) {
			t.Fatal("Unix authority widened to another digest")
		}
	}
	var forged MemcachedUnixReleaseAuthority
	if json.Unmarshal([]byte("{\"verified\":true,\"version\":\""+MemcachedUnixVersion+"\",\"image\":\""+MemcachedDigestImage+"\"}"), &forged) != nil || forged.Matches(MemcachedUnixVersion, digest) {
		t.Fatal("deserializable native Unix authority")
	}
	if _, err := VerifyMemcachedUnixReleaseEnvelope(context.Background(), in, MemcachedUnixVersion, digest); err == nil {
		t.Fatal("fixture key substituted for the public compiled official trust root")
	}
	if panelFeatureAvailable(MemcachedUnixFeature) != (runtime.GOOS == "linux") {
		t.Fatal("compiled Unix capability must match the Linux implementation, not a fixture callback")
	}
}

func TestMemcachedUnixEnvelopeCannotBorrowPublishedLegacyAuthorityOrFixtureAvailability(t *testing.T) {
	client, in := memcachedUnixEnvelopeFixture(t, nil)
	digest := hashRuleFeedFile(in.AppManifest)
	if _, err := verifyMemcachedReleaseEnvelope(context.Background(), client, MemcachedReleaseEnvelope(in), MemcachedDigestVersion, digest); err == nil {
		t.Fatal("unchanged compat2 verifier accepted the independent Unix release")
	}
	oldClient, old, _ := memcachedEnvelopeFixture(t, DefaultBaseURL)
	if _, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), oldClient, MemcachedUnixReleaseEnvelope(old), MemcachedUnixVersion, hashRuleFeedFile(old.AppManifest), memcachedUnixEnvelopeFixtureHandlers); err == nil {
		t.Fatal("legacy envelope borrowed the Unix handler")
	}
	for _, missing := range []string{MemcachedDigestFeature, MemcachedUnixFeature} {
		available := func(f string) bool { return f != missing }
		if _, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), client, in, MemcachedUnixVersion, digest, available); err == nil {
			t.Fatal("missing independent compiled handler accepted", missing)
		}
	}
	if _, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), client, in, MemcachedUnixVersion, digest, nil); err == nil {
		t.Fatal("nil compiled capability proof accepted")
	}
}

func TestMemcachedUnixEnvelopeRejectsCorrectlySignedWrongContract(t *testing.T) {
	changes := map[string]func(*Manifest){
		"withdrawn-prototype": func(m *Manifest) { m.Version = "1.6.45-compat3" },
		"future":              func(m *Manifest) { m.Version = "1.6.45-compat5" },
		"mutable-tag":         func(m *Manifest) { m.Delivery.Image = "memcached:1.6.45-alpine" },
		"foreign-image":       func(m *Manifest) { m.Delivery.Image = "redis:8.2" },
		"foreign-provider":    func(m *Manifest) { m.Delivery.Provider = "runtime" },
		"foreign-target":      func(m *Manifest) { m.Delivery.Target = "redis-cache" },
		"foreign-route":       func(m *Manifest) { m.Delivery.ManageRoute = "files" },
		"missing-handler":     func(m *Manifest) { m.RequiredPanelFeatures = []string{MemcachedDigestFeature} },
		"borrowed-prototype": func(m *Manifest) {
			m.RequiredPanelFeatures = []string{MemcachedDigestFeature, "compose-memcached-sandbox-v1"}
		},
		"duplicate-handler": func(m *Manifest) { m.RequiredPanelFeatures = []string{MemcachedUnixFeature, MemcachedUnixFeature} },
		"not-ready":         func(m *Manifest) { m.Stage = "planned" },
		"legacy-health":     func(m *Manifest) { m.Health = Health{Probe: "compose", Target: "memcached-cache"} },
		"TCP-health":        func(m *Manifest) { m.Health = Health{Probe: "tcp", Target: "version"} },
		"foreign-workspace": func(m *Manifest) { m.Health.Target = "redis-workspace" },
		"missing-health":    func(m *Manifest) { m.Health = Health{} },
		"discard-evidence":  func(m *Manifest) { m.Uninstall.PreserveData = false },
		"skip-references":   func(m *Manifest) { m.Uninstall.ReferenceCheck = false },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			client, in := memcachedUnixEnvelopeFixture(t, change)
			a, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), client, in, MemcachedUnixVersion, hashRuleFeedFile(in.AppManifest), memcachedUnixEnvelopeFixtureHandlers)
			if err == nil || a.Matches(MemcachedUnixVersion, hashRuleFeedFile(in.AppManifest)) {
				t.Fatal("a valid signature authorized an unsupported native contract")
			}
		})
	}
}

func TestMemcachedUnixEnvelopeRejectsUnboundBytesIdentityContextAndKey(t *testing.T) {
	client, in := memcachedUnixEnvelopeFixture(t, nil)
	wire, _ := json.Marshal(in)
	for _, scenario := range []string{"catalog", "manifest", "signature", "hash", "version", "client", "key", "origin", "nil-context", "canceled", "empty", "large"} {
		t.Run(scenario, func(t *testing.T) {
			candidate, err := DecodeMemcachedUnixReleaseEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			copy := &Client{BaseURL: client.BaseURL, PublicKey: append(ed25519.PublicKey(nil), client.PublicKey...)}
			ctx, version, digest := context.Background(), MemcachedUnixVersion, hashRuleFeedFile(candidate.AppManifest)
			switch scenario {
			case "catalog":
				candidate.Catalog[0] ^= 1
			case "manifest":
				candidate.AppManifest = append(candidate.AppManifest, ' ')
			case "signature":
				candidate.Signature[0] ^= 1
			case "hash":
				digest = strings.Repeat("0", 64)
			case "version":
				version = MemcachedDigestVersion
			case "client":
				copy = nil
			case "key":
				copy.PublicKey = make([]byte, 32)
			case "origin":
				copy.BaseURL += "/foreign"
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "empty":
				candidate.Catalog = nil
			case "large":
				candidate.Catalog = bytes.Repeat([]byte(" "), maxCatalogBytes+1)
			}
			a, err := verifyMemcachedUnixReleaseEnvelope(ctx, copy, candidate, version, digest, memcachedUnixEnvelopeFixtureHandlers)
			if err == nil || a.Matches(version, digest) {
				t.Fatal("unbound signed Unix authority accepted")
			}
		})
	}
}

func TestMemcachedUnixEnvelopeSharesClosedWireNotLegacyExecutionAuthority(t *testing.T) {
	_, in := memcachedUnixEnvelopeFixture(t, nil)
	valid, _ := json.Marshal(in)
	for _, raw := range [][]byte{
		append(append([]byte(nil), valid...), valid...),
		[]byte("null"), []byte("{}"),
		[]byte("{\"catalog\":[],\"signature\":\"YQ==\",\"app_manifest\":\"YQ==\"}"),
		bytes.Replace(valid, []byte("\"catalog\":"), []byte("\"catalog\":\"YQ==\",\"catalog\":"), 1),
		bytes.Replace(valid, []byte("\"signature\":"), []byte("\"Signature\":"), 1),
		bytes.Repeat([]byte(" "), MaxMemcachedReleaseEnvelopeBytes+1),
	} {
		if _, err := DecodeMemcachedUnixReleaseEnvelope(raw); err == nil {
			t.Fatal("ambiguous or oversized Unix transfer accepted")
		}
	}
}
