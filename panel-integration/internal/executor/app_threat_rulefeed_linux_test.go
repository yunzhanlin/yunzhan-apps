//go:build linux

package executor

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
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/rulefeed"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func threatRuleFeedFixture(t *testing.T, variable string) (appcatalog.RuleFeedEnvelope, *appcatalog.Client, string) {
	t.Helper()
	var contents bytes.Buffer
	tarWriter := tar.NewWriter(&contents)
	for _, name := range []string{"LICENSE", "BSD-License.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "rulefeed", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: "rules/" + name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	rules := []byte(`alert http any any -> $` + variable + ` any (msg:"own immutable store fixture";sid:2000001;rev:1;)` + "\n")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "rules/emerging-fixture.rules", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(rules))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(rules); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zipWriter := gzip.NewWriter(&compressed)
	if _, err := zipWriter.Write(contents.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	source, err := rulefeed.ReadETOpen(context.Background(), bytes.NewReader(compressed.Bytes()), core.Hash(compressed.String()))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := rulefeed.Build(source, rulefeed.Profile{Categories: []string{"emerging-fixture"}, Variables: []string{variable}, MaxEnabled: 128})
	if err != nil {
		t.Fatal(err)
	}
	feed := appcatalog.RuleFeed{ID: "et-open-web-20261009", ManifestSHA256: core.Hash(string(bundle.Files["manifest.json"]))}
	names := []string{}
	for name := range bundle.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		feed.Assets = append(feed.Assets, appcatalog.RuleFeedAsset{Name: name, SHA256: core.Hash(string(bundle.Files[name])), Bytes: len(bundle.Files[name])})
	}
	manifest := appcatalog.Manifest{SchemaVersion: 1, ID: "network-threat-detection", Name: "Own data store fixture", Category: "professional", Version: "1.3.0", Summary: "own bounded data-only store fixture", Stage: "ready", Risk: "maintained", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "network-threat-detection", ManageRoute: "app-modules"}, Capabilities: []string{"passive IDS"}, RuleFeeds: []appcatalog.RuleFeed{feed}}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	appSHA := core.Hash(string(manifestRaw))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := appcatalog.New("https://owned-rulefeed-fixture.invalid", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil)
	if err != nil {
		t.Fatal(err)
	}
	item := appcatalog.CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: manifest.Stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: trust.BaseURL + "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/manifest.json", SHA256: appSHA}
	catalogRaw, err := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T00:00:00Z", Apps: []appcatalog.CatalogItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	// No transport is needed by the privileged data store.
	trust.HTTP = nil
	return appcatalog.RuleFeedEnvelope{Catalog: catalogRaw, Signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalogRaw))), AppManifest: manifestRaw, FeedID: feed.ID, Files: bundle.Files}, trust, appSHA
}

func threatRuleFeedTestStore(t *testing.T, trust *appcatalog.Client) threatIDSRuleFeedStore {
	t.Helper()
	base := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	return threatIDSRuleFeedStore{base: base, trust: trust, now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }}
}

func TestThreatIDSRuleFeedDataOnlyStoreAndIdempotency(t *testing.T) {
	in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
	store := threatRuleFeedTestStore(t, trust)
	record, err := store.install(context.Background(), in, "1.3.0", appSHA)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != "verified-data-only" || record.Format != 1 || record.FeedID != in.FeedID || record.RuleManifestSHA != core.Hash(string(in.Files["manifest.json"])) {
		t.Fatal("false native proof or wrong data binding", record)
	}
	name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
	entries, err := os.ReadDir(filepath.Join(store.base, name))
	if err != nil || len(entries) != 10 {
		t.Fatal("unclosed published files", err)
	}
	before := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(store.base, name, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = core.Hash(string(data))
	}
	second, err := store.install(context.Background(), in, "1.3.0", appSHA)
	if err != nil || second != record {
		t.Fatal("idempotent reuse failed", err)
	}
	parents, _ := os.ReadDir(store.base)
	if len(parents) != 1 {
		t.Fatal("idempotent install allocated another stage")
	}
	for name, sha := range before {
		data, err := os.ReadFile(filepath.Join(store.base, threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA), name))
		if err != nil || core.Hash(string(data)) != sha {
			t.Fatal("idempotent install changed stored data", name)
		}
	}
}

func TestThreatIDSRuleFeedRejectsBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"signature", "catalog", "member", "extra-member", "app-binding", "version", "expired", "future", "undefined-variable", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			variable := "HOME_NET"
			if scenario == "undefined-variable" {
				variable = "HTTP_SERVERS"
			}
			in, trust, appSHA := threatRuleFeedFixture(t, variable)
			store := threatRuleFeedTestStore(t, trust)
			ctx := context.Background()
			version := "1.3.0"
			switch scenario {
			case "signature":
				in.Signature[0] ^= 1
			case "catalog":
				in.Catalog[0] ^= 1
			case "member":
				in.Files["et-open.rules"][0] ^= 1
			case "extra-member":
				in.Files["run.sh"] = []byte("invalid")
			case "app-binding":
				appSHA = strings.Repeat("0", 64)
			case "version":
				version = "1.2.0"
			case "expired":
				store.now = func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
			case "future":
				store.now = func() time.Time { return time.Date(2026, 10, 8, 23, 59, 59, 0, time.UTC) }
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if _, err := store.install(ctx, in, version, appSHA); err == nil {
				t.Fatal("invalid data accepted", scenario)
			}
			entries, _ := os.ReadDir(store.base)
			if len(entries) != 0 {
				t.Fatal("rejected data changed filesystem", scenario)
			}
		})
	}
}

func TestThreatIDSRuleFeedReadRechecksCompleteIdentity(t *testing.T) {
	for _, scenario := range []string{"rule-bytes", "license-bytes", "signature", "app-manifest", "record", "duplicate-record", "extra-file", "symlink", "hardlink", "mode", "directory-mode", "expired", "trust-key"} {
		t.Run(scenario, func(t *testing.T) {
			in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
			store := threatRuleFeedTestStore(t, trust)
			record, err := store.install(context.Background(), in, "1.3.0", appSHA)
			if err != nil {
				t.Fatal(err)
			}
			name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
			base := filepath.Join(store.base, name)
			mutate := func(filename string) {
				path := filepath.Join(base, filename)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "rule-bytes":
				mutate("et-open.rules")
			case "license-bytes":
				mutate("LICENSE")
			case "signature":
				mutate("catalog.sig")
			case "app-manifest":
				mutate("app-manifest.json")
			case "record":
				mutate("provenance.json")
			case "duplicate-record":
				path := filepath.Join(base, "provenance.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data = append([]byte(`{"STATE":"verified-data-only",`), data[1:]...)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-file":
				if err := os.WriteFile(filepath.Join(base, "run.sh"), []byte("untrusted"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := filepath.Join(base, "LICENSE")
				if err := os.Rename(path, filepath.Join(store.base, "retained-license")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../retained-license", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(base, "et-open.rules"), filepath.Join(store.base, "retained-hardlink")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Join(base, "et-open.rules"), 0664); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(base, 0775); err != nil {
					t.Fatal(err)
				}
			case "expired":
				store.now = func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
			case "trust-key":
				store.trust = &appcatalog.Client{BaseURL: trust.BaseURL, PublicKey: make(ed25519.PublicKey, 32)}
			}
			if _, err := store.read(context.Background(), name, "1.3.0", appSHA); err == nil {
				t.Fatal("modified or stale data adopted", scenario)
			}
		})
	}
}

func TestThreatIDSRuleFeedFaultsRetainStagesAndNeverActivate(t *testing.T) {
	for _, point := range []string{"stage-created", "member-written:manifest.json", "member-written:et-open.rules", "data-synced", "published"} {
		t.Run(point, func(t *testing.T) {
			in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
			store := threatRuleFeedTestStore(t, trust)
			store.checkpoint = func(actual string) error {
				if actual == point {
					return errors.New("own injected interruption")
				}
				return nil
			}
			if _, err := store.install(context.Background(), in, "1.3.0", appSHA); err == nil {
				t.Fatal("injected interruption reported success")
			}
			entries, err := os.ReadDir(store.base)
			if err != nil || len(entries) != 1 {
				t.Fatal("failed evidence erased or extra publication", err)
			}
			retained := entries[0].Name()
			info, err := os.Lstat(filepath.Join(store.base, retained))
			if err != nil {
				t.Fatal(err)
			}
			if point != "published" && (!strings.HasPrefix(retained, ".stage-") || info.Mode().Perm() != 0700) {
				t.Fatal("partial data escaped private stage")
			}
			store.checkpoint = nil
			record, err := store.install(context.Background(), in, "1.3.0", appSHA)
			if err != nil || record.State != "verified-data-only" {
				t.Fatal("explicit retry failed or claimed activation", err)
			}
			if _, err := os.Lstat(filepath.Join(store.base, retained)); err != nil {
				t.Fatal("retry erased retained original stage", err)
			}
			entries, _ = os.ReadDir(store.base)
			wanted := 2
			if point == "published" {
				wanted = 1
			}
			if len(entries) != wanted {
				t.Fatal("wrong retry publication count", len(entries), wanted)
			}
		})
	}
}

func TestThreatIDSRuleFeedNoReplaceAndStorageBudget(t *testing.T) {
	for _, scenario := range []string{"foreign-existing", "concurrent-target", "eight-stages", "unknown-entry"} {
		t.Run(scenario, func(t *testing.T) {
			in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
			store := threatRuleFeedTestStore(t, trust)
			target := filepath.Join(store.base, threatIDSRuleFeedName(in.FeedID, core.Hash(string(in.Files["manifest.json"]))))
			foreign := func() {
				if err := os.Mkdir(target, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "unmanaged.txt"), []byte("must survive unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "foreign-existing":
				foreign()
			case "concurrent-target":
				store.checkpoint = func(point string) error {
					if point == "data-synced" {
						foreign()
					}
					return nil
				}
			case "eight-stages":
				for i := 0; i < 8; i++ {
					if err := os.Mkdir(filepath.Join(store.base, ".stage-"+core.ID()), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "unknown-entry":
				if err := os.WriteFile(filepath.Join(store.base, "unknown.txt"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.install(context.Background(), in, "1.3.0", appSHA); err == nil {
				t.Fatal("unknown target or exhausted budget accepted")
			}
			if scenario == "foreign-existing" || scenario == "concurrent-target" {
				data, err := os.ReadFile(filepath.Join(target, "unmanaged.txt"))
				if err != nil || string(data) != "must survive unchanged" {
					t.Fatal("foreign target replaced", err)
				}
			}
			entries, _ := os.ReadDir(store.base)
			if scenario == "eight-stages" && len(entries) != 8 || scenario == "unknown-entry" && len(entries) != 1 || scenario == "foreign-existing" && len(entries) != 1 {
				t.Fatal("refused request mutated retained storage")
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".stage-") {
					info, err := entry.Info()
					if err != nil || info.Mode().Perm() != 0700 {
						t.Fatal("failed stage not sealed", err)
					}
				}
			}
		})
	}
}

func TestThreatIDSRuleFeedPolicyWindowAndBoundedProfile(t *testing.T) {
	in, trust, appSHA := threatRuleFeedFixture(t, "HOME_NET")
	store := threatRuleFeedTestStore(t, trust)
	_, bundle, err := store.verify(context.Background(), in, "1.3.0", appSHA)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []time.Time{time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 22, 23, 59, 59, 0, time.UTC)} {
		if err := threatIDSRuleFeedPolicy(valid, in.FeedID, bundle); err != nil {
			t.Fatal("valid window rejected", err)
		}
	}
	bundle.Manifest.EnabledRuleCount = 2049
	if err := threatIDSRuleFeedPolicy(store.now(), in.FeedID, bundle); err == nil {
		t.Fatal("unaccepted native resource profile permitted")
	}
	if err := threatIDSRuleFeedPolicy(store.now(), in.FeedID, nil); err == nil {
		t.Fatal("absent bundle accepted")
	}
}
