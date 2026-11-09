//go:build linux

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type threatRuleDataFixture struct {
	in      appcatalog.RuleFeedEnvelope
	trust   *appcatalog.Client
	private ed25519.PrivateKey
	appSHA  string
	data    appcatalog.RuleDataCatalog
}

func threatRuleDataFixtureNew(t *testing.T) *threatRuleDataFixture {
	return threatRuleDataFixtureVersion(t, "1.3.0")
}

func threatRuleDataFixtureVersion(t *testing.T, version string) *threatRuleDataFixture {
	t.Helper()
	in, _, _ := threatRuleFeedFixture(t, "HOME_NET")
	var manifest appcatalog.Manifest
	if err := json.Unmarshal(in.AppManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Version = version
	feed := manifest.RuleFeeds[0]
	manifest.RuleFeeds = nil
	manifest.RuleDataChannel = &appcatalog.RuleDataChannel{ID: "et-open-web-bsd-v1", Format: 1, Engine: "suricata-8.0"}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	trust, err := appcatalog.New("https://owned-channel-fixture.invalid", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil)
	if err != nil {
		t.Fatal(err)
	}
	trust.HTTP = nil
	in.AppManifest, _ = json.Marshal(manifest)
	appSHA := core.Hash(string(in.AppManifest))
	item := appcatalog.CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: manifest.Stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: trust.BaseURL + "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/manifest.json", SHA256: appSHA}
	in.Catalog, _ = json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T10:00:00Z", Apps: []appcatalog.CatalogItem{item}})
	in.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, in.Catalog)))
	f := &threatRuleDataFixture{in: in, trust: trust, private: private, appSHA: appSHA, data: appcatalog.RuleDataCatalog{SchemaVersion: 1, Channel: "et-open-web-bsd-v1", Sequence: 5, PublishedAt: "2026-10-09T10:00:00Z", ExpiresAt: "2026-10-10T10:00:00Z", Feed: feed}}
	f.sign()
	return f
}

func TestThreatIDSRuleFeedProfileCandidateRequiresOriginalSignaturesAndFreshData(t *testing.T) {
	for _, scenario := range []string{"valid", "changed-rules", "changed-data-signature", "changed-app-signature", "expired-data", "different-selection"} {
		t.Run(scenario, func(t *testing.T) {
			version := core.SoftwareImplementationVersion("network-threat-detection")
			f := threatRuleDataFixtureVersion(t, version)
			store := threatRuleFeedTestStore(t, f.trust)
			record, err := store.install(context.Background(), f.in, version, f.appSHA)
			if err != nil {
				t.Fatal(err)
			}
			name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
			selection := core.NetworkIDSRuleFeedSelection{FeedID: record.FeedID, AppVersion: version, AppManifestSHA: f.appSHA, RuleManifestSHA: record.RuleManifestSHA}
			switch scenario {
			case "changed-rules", "changed-data-signature", "changed-app-signature":
				file := "et-open.rules"
				if scenario == "changed-data-signature" {
					file = "rule-data-catalog.sig"
				}
				if scenario == "changed-app-signature" {
					file = "catalog.sig"
				}
				path := filepath.Join(store.base, name, file)
				data, _ := os.ReadFile(path)
				data[0] ^= 1
				mode := os.FileMode(0600)
				if file == "et-open.rules" {
					mode = 0644
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			case "expired-data":
				store.now = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
			case "different-selection":
				selection.AppManifestSHA = core.Hash("not-authorized")
			}
			text, err := store.ruleDataYAML(context.Background(), threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}, selection)
			if (err == nil) != (scenario == "valid") || err != nil && text != "" {
				t.Fatalf("unverified candidate exposed: %v", err)
			}
			entries, _ := os.ReadDir(store.base)
			if len(entries) != 1 {
				t.Fatal("candidate approval mutated stored data")
			}
		})
	}
}
func (f *threatRuleDataFixture) sign() {
	f.in.FeedID = f.data.Feed.ID
	f.in.DataCatalog, _ = json.Marshal(f.data)
	f.in.DataSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, append([]byte("yunzhan-rulefeed-channel-v1\n"), f.in.DataCatalog...))))
}

func TestThreatIDSRuleFeedChannelStoreRetainsTwoIndependentSignatures(t *testing.T) {
	f := threatRuleDataFixtureNew(t)
	store := threatRuleFeedTestStore(t, f.trust)
	record, err := store.install(context.Background(), f.in, "1.3.0", f.appSHA)
	if err != nil {
		t.Fatal(err)
	}
	name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
	entries, _ := os.ReadDir(filepath.Join(store.base, name))
	if record.Format != 2 || len(entries) != 12 || record.DataCatalogSHA != core.Hash(string(f.in.DataCatalog)) || record.DataSignatureSHA != core.Hash(string(f.in.DataSignature)) {
		t.Fatal("missing original data authority", record)
	}
	read, err := store.read(context.Background(), name, "1.3.0", f.appSHA)
	if err != nil || read != record {
		t.Fatalf("data independently read: %v", err)
	}
	second, err := store.install(context.Background(), f.in, "1.3.0", f.appSHA)
	if err != nil || second != record {
		t.Fatalf("immutable reuse: %v", err)
	}
	for _, file := range []string{"rule-data-catalog.json", "rule-data-catalog.sig"} {
		info, err := os.Lstat(filepath.Join(store.base, name, file))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("original authority not private")
		}
	}
	path := filepath.Join(store.base, name, "rule-data-catalog.sig")
	raw, _ := os.ReadFile(path)
	raw[0] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.read(context.Background(), name, "1.3.0", f.appSHA); err == nil {
		t.Fatal("changed independent signature adopted")
	}
}

func TestThreatIDSRuleFeedChannelProgressSurvivesRestartAndExpiredHistory(t *testing.T) {
	for _, scenario := range []string{"lower-sequence", "same-sequence-rewrite", "older-publication", "older-feed", "valid-forward", "expired-history-forward", "damaged-history", "downgraded-history"} {
		t.Run(scenario, func(t *testing.T) {
			f := threatRuleDataFixtureNew(t)
			store := threatRuleFeedTestStore(t, f.trust)
			record, err := store.install(context.Background(), f.in, "1.3.0", f.appSHA)
			if err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(store.base, threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA))
			before := f.appSHA
			// Reconstruct the store: no in-memory previous authority is carried over.
			store = threatIDSRuleFeedStore{base: store.base, trust: f.trust, now: store.now}
			f.data.Sequence = 6
			f.data.Feed.ID = "et-open-web-20261010"
			f.data.PublishedAt = "2026-10-10T10:00:00Z"
			f.data.ExpiresAt = "2026-10-11T10:00:00Z"
			store.now = func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }
			switch scenario {
			case "lower-sequence":
				f.data.Sequence = 4
			case "same-sequence-rewrite":
				f.data.Sequence = 5
			case "older-publication":
				f.data.Feed.ID = "et-open-web-20261009"
				f.data.PublishedAt = "2026-10-09T09:00:00Z"
				f.data.ExpiresAt = "2026-10-11T09:00:00Z"
			case "older-feed":
				f.data.Feed.ID = "et-open-web-20261008"
			case "expired-history-forward":
				f.data.Feed.ID = "et-open-web-20261011"
				f.data.PublishedAt = "2026-10-11T10:00:00Z"
				f.data.ExpiresAt = "2026-10-12T10:00:00Z"
				store.now = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
			case "damaged-history":
				if err := os.WriteFile(filepath.Join(original, "rule-data-catalog.json"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "downgraded-history":
				fake := record
				fake.Format = 1
				fake.DataCatalogSHA = ""
				fake.DataSignatureSHA = ""
				data, _ := json.Marshal(fake)
				if err := os.WriteFile(filepath.Join(original, "provenance.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.sign()
			_, err = store.install(context.Background(), f.in, "1.3.0", f.appSHA)
			expectSuccess := scenario == "valid-forward" || scenario == "expired-history-forward"
			if (err == nil) != expectSuccess {
				t.Fatalf("history progress result %v expected success %v", err, expectSuccess)
			}
			entries, _ := os.ReadDir(store.base)
			want := 1
			if expectSuccess {
				want = 2
			}
			if len(entries) != want || f.appSHA != before {
				t.Fatal("history or immutable app release changed")
			}
			if _, err := os.Stat(original); err != nil {
				t.Fatal("original history deleted")
			}
		})
	}
}
