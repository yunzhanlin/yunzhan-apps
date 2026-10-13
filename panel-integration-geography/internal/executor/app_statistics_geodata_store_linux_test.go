//go:build linux

package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

// Synthetic MMDB and test-only signing key. These filesystem tests prove
// transaction/permission boundaries, not original-key provider acceptance,
// real visitor traffic, actual power-loss, or production update delivery.
func geoStoreMMDBValue(v any) []byte {
	header := func(kind byte, n int) []byte {
		if n >= 29 {
			panic("oversized fixture")
		}
		if kind >= 8 {
			return []byte{byte(n), kind - 7}
		}
		return []byte{kind<<5 | byte(n)}
	}
	switch x := v.(type) {
	case string:
		return append(header(2, len(x)), []byte(x)...)
	case uint32:
		return binary.BigEndian.AppendUint32(header(6, 4), x)
	case uint64:
		return binary.BigEndian.AppendUint64(header(9, 8), x)
	case map[string]any:
		b := header(7, len(x))
		for k, v := range x {
			b = append(b, geoStoreMMDBValue(k)...)
			b = append(b, geoStoreMMDBValue(v)...)
		}
		return b
	case []any:
		b := header(11, len(x))
		for _, v := range x {
			b = append(b, geoStoreMMDBValue(v)...)
		}
		return b
	}
	panic("unsupported fixture")
}
func geoStoreMMDB(release string) []byte {
	month, _ := time.Parse("2006-01", release)
	data := map[string]any{"country": map[string]any{"iso_code": "US", "names": map[string]any{"en": "Synthetic country"}}, "city": map[string]any{"names": map[string]any{"en": "Synthetic " + release}}}
	out := append([]byte{0, 0, 17, 0, 0, 17}, make([]byte, 16)...)
	out = append(out, geoStoreMMDBValue(data)...)
	out = append(out, []byte("\xAB\xCD\xEFMaxMind.com")...)
	meta := map[string]any{"node_count": uint32(1), "record_size": uint32(24), "ip_version": uint32(6), "database_type": "DBIP-City-Lite", "binary_format_major_version": uint32(2), "binary_format_minor_version": uint32(0), "build_epoch": uint64(month.Unix()), "languages": []any{"en"}, "description": map[string]any{"en": "Synthetic root store"}}
	return append(out, geoStoreMMDBValue(meta)...)
}

type geoStoreTransport func(*http.Request) (*http.Response, error)

func (f geoStoreTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type geoStoreFixture struct {
	store        statisticsGeoStore
	key          ed25519.PrivateKey
	app          appcatalog.GeoDataEnvelope
	sha          string
	downloads    int
	failDownload bool
	payloads     map[string][]byte
}

func geoStoreRootFixture(t *testing.T) *geoStoreFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-private filesystem store acceptance requires Linux root under trusted /var")
	}
	parent := "/var/lib/panel-executor"
	if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := statisticsGeoParents(parent); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(parent, "statistics-geodata-test24beqg-")
	if err != nil {
		t.Fatal(err)
	}
	baseIdentity, err := os.Lstat(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // Only this test's exclusively created, validated scope.
		visible, identityErr := os.Lstat(base)
		if identityErr != nil || !os.SameFile(baseIdentity, visible) || !strings.HasPrefix(filepath.Base(base), "statistics-geodata-test24beqg-") || ruleFeedStoreOwned(base, true, 0700) != nil {
			t.Error("refused fixture cleanup after foreign identity change")
			return
		}
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	trust, err := appcatalog.New("https://owned-geodata-fixture.invalid", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := appcatalog.Manifest{SchemaVersion: 1, ID: "website-statistics-v2", Name: "Synthetic geo store", Category: "professional", Version: "2.6.0", Summary: "Explicit test fixture", Stage: "ready", Risk: "maintained", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "website-statistics-v2", ManageRoute: "app-modules"}, Capabilities: []string{"bounded offline statistics"}, RequiredPanelFeatures: []string{appcatalog.StatisticsCursorRetirementFeature, appcatalog.StatisticsRequestIdentityFeature, appcatalog.StatisticsGeographyFeature}, GeoDataChannel: &appcatalog.GeoDataChannel{ID: geodata.Channel, Format: 1}}
	manifest, _ := json.Marshal(m)
	sha := core.Hash(string(manifest))
	item := appcatalog.CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: trust.BaseURL + "/dist/apps/website-statistics-v2/2.6.0/manifest.json", SHA256: sha}
	catalog, _ := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-13T00:00:00Z", Apps: []appcatalog.CatalogItem{item}})
	f := &geoStoreFixture{store: statisticsGeoStore{base: filepath.Join(base, "store"), trust: trust, now: func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }}, key: key, sha: sha, app: appcatalog.GeoDataEnvelope{AppCatalog: catalog, AppSignature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, catalog))), AppManifest: manifest}, payloads: map[string][]byte{}}
	trust.HTTP = &http.Client{Transport: geoStoreTransport(func(r *http.Request) (*http.Response, error) {
		f.downloads++
		if f.failDownload {
			return nil, errors.New("synthetic network failure")
		}
		payload, ok := f.payloads[r.URL.String()]
		if !ok {
			t.Fatalf("unrecognized provider source: %s", r.URL)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("provider received credentials")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: int64(len(payload)), Request: r}, nil
	})}
	return f
}
func (f *geoStoreFixture) envelope(t *testing.T, release string) appcatalog.GeoDataEnvelope {
	t.Helper()
	raw := geoStoreMMDB(release)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(raw)
	w.Close()
	compressed := bytes.Clone(b.Bytes())
	month, _ := time.Parse("2006-01", release)
	m := geodata.Manifest{Format: 1, Channel: geodata.Channel, Release: release, BuildEpoch: uint64(month.Unix()), CompressedBytes: int64(len(compressed)), CompressedSHA256: core.Hash(string(compressed)), Bytes: int64(len(raw)), SHA256: core.Hash(string(raw)), Source: "https://download.db-ip.com/free/dbip-city-lite-" + release + ".mmdb.gz", License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	manifest, _ := json.Marshal(m)
	in := f.app
	in.DataManifest = manifest
	in.DataSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, append([]byte(geodata.SignatureDomain), manifest...))))
	f.payloads[m.Source] = compressed
	return in
}
func (f *geoStoreFixture) install(t *testing.T, release string) appcatalog.GeoDataAuthority {
	t.Helper()
	a, s, err := f.store.install(context.Background(), f.envelope(t, release), f.sha)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Lookup("8.8.8.8"); got.Status != "located" || got.City != "Synthetic "+release {
		t.Fatal(got)
	}
	s.Close()
	return a
}
func (f *geoStoreFixture) selected(t *testing.T) statisticsGeoSelector {
	t.Helper()
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, _, _, err := f.store.selector(root.Root)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func TestStatisticsGeoStoreNativeInstallReplayRollbackAndHighWater(t *testing.T) {
	f := geoStoreRootFixture(t)
	old := f.install(t, "2026-09")
	current := f.install(t, "2026-10")
	if f.downloads != 2 || f.selected(t).Dataset != geoStoreName(current) || f.selected(t).Previous != geoStoreName(old) {
		t.Fatal("wrong selection or download count")
	}
	_, snapshot, err := f.store.install(context.Background(), current.Envelope(), f.sha)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Close()
	if f.downloads != 2 {
		t.Fatal("replay downloaded or replaced immutable data")
	}
	rolled, err := f.store.rollback(context.Background(), geoStoreName(old))
	if err != nil {
		t.Fatal(err)
	}
	rolled.Close()
	if f.selected(t).Dataset != geoStoreName(old) || f.selected(t).Previous != geoStoreName(current) {
		t.Fatal("explicit rollback not retained")
	}
	if _, s, err := f.store.install(context.Background(), old.Envelope(), f.sha); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("rollback lowered immutable anti-replay history")
	}
	if f.downloads != 2 {
		t.Fatal("rejected downgrade contacted provider")
	}
	for _, a := range []appcatalog.GeoDataAuthority{old, current} {
		root, err := os.OpenRoot(filepath.Join(f.store.base, geoStoreName(a)))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"database.mmdb.gz", "NOTICE.txt", "envelope.json"} {
			info, err := root.Lstat(name)
			if err != nil || !moduleRecordInfo(info, false, false) {
				t.Fatal("unsafe capsule member", name, err)
			}
		}
		root.Close()
	}
}
func TestStatisticsGeoStoreNativeDownloadFailurePreservesSelectedBytes(t *testing.T) {
	f := geoStoreRootFixture(t)
	old := f.install(t, "2026-09")
	before, err := os.ReadFile(filepath.Join(f.store.base, "selected.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.failDownload = true
	if _, s, err := f.store.install(context.Background(), f.envelope(t, "2026-10"), f.sha); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("download failure accepted")
	}
	after, _ := os.ReadFile(filepath.Join(f.store.base, "selected.json"))
	if !bytes.Equal(before, after) || f.selected(t).Dataset != geoStoreName(old) {
		t.Fatal("failed download changed active selection")
	}
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, snapshot, _, err := f.store.load(context.Background(), root.Root, geoStoreName(old))
	if err != nil {
		t.Fatal("last good cannot load", err)
	}
	snapshot.Close()
}
func TestStatisticsGeoStoreNativeFaultBoundariesRetainOldOrCommittedState(t *testing.T) {
	for _, point := range []string{"stage-created", "download-complete", "database-verified", "capsule-published", "selector-written", "selector-committed"} {
		t.Run(point, func(t *testing.T) {
			f := geoStoreRootFixture(t)
			old := f.install(t, "2026-09")
			in := f.envelope(t, "2026-10")
			candidate, err := f.store.trust.VerifyGeoDataEnvelope(in, "2.6.0", f.sha, f.store.now(), nil)
			if err != nil {
				t.Fatal(err)
			}
			f.store.fault = func(p string) error {
				if p == point {
					return errors.New("synthetic interruption at " + p)
				}
				return nil
			}
			if _, s, err := f.store.install(context.Background(), in, f.sha); err == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("fault ignored")
			}
			selected := f.selected(t)
			want := geoStoreName(old)
			if point == "selector-committed" {
				want = geoStoreName(candidate)
			}
			if selected.Dataset != want {
				t.Fatal("false rollback or premature publication", selected, want)
			}
			f.store.fault = nil
			root, err := f.store.open(false)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, loaded, _, err := f.store.load(context.Background(), root.Root, selected.Dataset)
			if err != nil {
				t.Fatal("selected dataset cannot independently verify", err)
			}
			loaded.Close()
		})
	}
}
func TestStatisticsGeoStoreNativeForeignMutationNeverPublishesOrRepairs(t *testing.T) {
	for _, point := range []string{"database-verified", "capsule-published", "selector-written"} {
		t.Run(point, func(t *testing.T) {
			f := geoStoreRootFixture(t)
			old := f.install(t, "2026-09")
			f.store.fault = func(p string) error {
				if p != point {
					return nil
				}
				entries, err := os.ReadDir(f.store.base)
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".stage-") || statisticsGeoName.MatchString(entry.Name()) && entry.Name() != geoStoreName(old) {
						path := filepath.Join(f.store.base, entry.Name(), "database.mmdb.gz")
						data, err := os.ReadFile(path)
						if err == nil && len(data) > 0 {
							data[0] ^= 1
							return os.WriteFile(path, data, 0600)
						}
					}
				}
				return errors.New("fixture mutation target missing")
			}
			if _, s, err := f.store.install(context.Background(), f.envelope(t, "2026-10"), f.sha); err == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("post-verification mutation accepted")
			}
			if f.selected(t).Dataset != geoStoreName(old) {
				t.Fatal("foreign mutation selected corrupt data")
			}
		})
	}
}
func TestStatisticsGeoStoreNativeUnsafeExistingDirectoryAndLockRefused(t *testing.T) {
	f := geoStoreRootFixture(t)
	if err := os.Mkdir(f.store.base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.store.base, 0755); err != nil {
		t.Fatal(err)
	}
	if _, s, err := f.store.install(context.Background(), f.envelope(t, "2026-10"), f.sha); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("unsafe existing directory repaired/adopted")
	}
	info, _ := os.Lstat(f.store.base)
	if info.Mode().Perm() != 0755 || f.downloads != 0 {
		t.Fatal("unsafe prior path changed")
	}
	// Explicit fixture repair only; production store never repairs such a path.
	if err := os.Chmod(f.store.base, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := geoStoreLock(root.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, s, err := f.store.install(context.Background(), f.envelope(t, "2026-10"), f.sha); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("concurrent writer lock bypassed")
	}
	if f.downloads != 0 {
		t.Fatal("busy store downloaded data")
	}
}
func TestStatisticsGeoStoreNativeFIFOAndHardlinkFailWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := geoStoreRootFixture(t)
			a := f.install(t, "2026-10")
			path := filepath.Join(f.store.base, geoStoreName(a), "database.mmdb.gz")
			if kind == "fifo" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Link(path, filepath.Join(filepath.Dir(f.store.base), "foreign-linked-data")); err != nil {
					t.Fatal(err)
				}
			}
			root, err := f.store.open(false)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			start := time.Now()
			if _, s, _, err := f.store.load(context.Background(), root.Root, geoStoreName(a)); err == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("unsafe data type or link count accepted")
			}
			if time.Since(start) > time.Second {
				t.Fatal("unsafe path blocked read")
			}
		})
	}
}

func TestStatisticsGeoSelectorIndependentClosedSchema(t *testing.T) {
	v := statisticsGeoSelector{Format: 1, Dataset: "dbip-city-lite-v1-2026-10-" + strings.Repeat("a", 64), Previous: "", UpdatedAt: "2026-10-13T12:00:00Z"}
	raw, _ := json.Marshal(v)
	var decoded statisticsGeoSelector
	if err := decodeStatisticsGeoSelector(raw, &decoded); err != nil || decoded != v {
		t.Fatal("valid non-WAF selector rejected", err, decoded)
	}
	for _, text := range []string{strings.Replace(string(raw), `"format":1`, `"Format":1`, 1), strings.Replace(string(raw), `"previous":"",`, "", 1), strings.Replace(string(raw), `"previous":""`, `"previous":null`, 1), `{"format":1,` + string(raw[1:]), string(raw) + ` {}`, strings.Replace(string(raw), `"format":1`, `"format":"1"`, 1), strings.Replace(string(raw), `"previous":""`, `"previous":[]`, 1)} {
		if decodeStatisticsGeoSelector([]byte(text), &decoded) == nil {
			t.Fatal("invalid selector admitted", text)
		}
	}
}

func TestStatisticsGeoStoreNativeForeignSameByteSelectorReplacementRefused(t *testing.T) {
	f := geoStoreRootFixture(t)
	old := f.install(t, "2026-09")
	path := filepath.Join(f.store.base, "selected.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	f.store.fault = func(point string) error {
		if point != "selector-written" {
			return nil
		}
		if err := os.Rename(path, filepath.Join(filepath.Dir(f.store.base), "retained-foreign-selector")); err != nil {
			return err
		}
		return os.WriteFile(path, before, 0600)
	}
	if _, snapshot, err := f.store.install(context.Background(), f.envelope(t, "2026-10"), f.sha); err == nil {
		if snapshot != nil {
			snapshot.Close()
		}
		t.Fatal("same-byte foreign selector inode was overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || os.SameFile(original, identity) || f.selected(t).Dataset != geoStoreName(old) {
		t.Fatal("foreign selector was repaired or clobbered")
	}
}

func TestStatisticsGeoStoreNativeContentHashRequiredEvenWithMatchingMetadata(t *testing.T) {
	f := geoStoreRootFixture(t)
	a := f.install(t, "2026-10")
	path := filepath.Join(f.store.base, geoStoreName(a), "database.mmdb.gz")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Deliberately provide the CURRENT metadata after corruption, so every
	// identity/timestamp comparison matches. Only the original signed hash can
	// prevent this from being treated as a verified publication.
	matching, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if f.store.publicationCurrent(context.Background(), root, geoStoreName(a), matching) {
		t.Fatal("matching metadata substituted for signed content integrity")
	}
}
