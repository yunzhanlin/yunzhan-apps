//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

// Synthetic public data and throwaway signing key. These Root filesystem
// models are not provider publication, an installed data ABI or live WAF proof.
type countryCacheFixture struct {
	store               countryCacheStore
	plan                countryCachePlan
	manifest, signature []byte
	payload             map[string][]byte
	downloads           int
	key                 ed25519.PrivateKey
}

func newCountryCacheFixture(t *testing.T) *countryCacheFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("country cache filesystem models require Linux root and trusted /var")
	}
	const parent = "/var/lib/panel-executor"
	if err := statisticsGeoParents(parent); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(parent, "waf-country-cache-test-")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		visible, err := os.Lstat(base)
		if err != nil || !os.SameFile(identity, visible) || !strings.HasPrefix(filepath.Base(base), "waf-country-cache-test-") || !moduleRecordInfo(visible, true, false) || statisticsGeoParents(base) != nil {
			t.Error("refused cleanup after private fixture root changed")
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
	sign := func(domain string, raw []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), raw...))))
	}
	parentManifest := geodata.Manifest{Format: 1, Channel: geodata.Channel, Release: "2026-10", BuildEpoch: 1790818881, CompressedBytes: 1, CompressedSHA256: strings.Repeat("b", 64), Bytes: 1, SHA256: strings.Repeat("a", 64), Source: "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	parentRaw, _ := json.Marshal(parentManifest)
	m := geodata.CountryManifest{Format: 1, Channel: geodata.CountryChannel, Release: parentManifest.Release, Revision: 1, BuildEpoch: parentManifest.BuildEpoch, ParentManifest: string(parentRaw), ParentSignature: string(sign(geodata.SignatureDomain, parentRaw)), GeneratorSHA256: strings.Repeat("c", 64), License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	f := &countryCacheFixture{key: key, store: countryCacheStore{base: filepath.Join(base, "cache"), trust: &appcatalog.Client{PublicKey: pub}, now: func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }}, payload: map[string][]byte{}}
	var assets []geodata.CountryAsset
	for _, record := range []struct{ code, prefix string }{{"CN", "8.8.4.0/24"}, {"US", "8.8.8.0/24"}} {
		var out bytes.Buffer
		metadata, err := geodata.EncodeCountryCIDR(context.Background(), geodata.CountryNetworkExport{ManifestSHA256: core.Hash(string(parentRaw)), DatabaseSHA256: parentManifest.SHA256, RecordsVisited: 1, Networks: []geodata.CountryNetwork{{Prefix: netip.MustParsePrefix(record.prefix), CountryCode: record.code}}}, &out)
		if err != nil {
			t.Fatal(err)
		}
		f.payload[record.code] = bytes.Clone(out.Bytes())
		assets = append(assets, geodata.CountryAsset{Code: record.code, Bytes: metadata.Bytes, SHA256: metadata.SHA256, Networks: metadata.Networks})
		m.Bytes += metadata.Bytes
		m.Networks += metadata.Networks
	}
	assetRaw, _ := json.Marshal(assets)
	m.AssetsJSON = string(assetRaw)
	f.manifest, _ = json.Marshal(m)
	f.signature = sign(geodata.CountrySignatureDomain, f.manifest)
	f.plan = countryCachePlan{1, core.ID(), core.Hash(string(f.manifest)), []string{"CN", "US"}}
	return f
}

func (f *countryCacheFixture) download(ctx context.Context, a geodata.CountryAuthority, code string, out *os.File) error {
	f.downloads++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a.SHA256() != f.plan.DataManifestSHA {
		return errors.New("fixture received foreign data authority")
	}
	_, err := out.Write(f.payload[code])
	return err
}
func (f *countryCacheFixture) stage() string {
	return filepath.Join(f.store.base, ".country-stage-"+f.plan.JobID)
}
func (f *countryCacheFixture) digest() string {
	raw, _ := countryCacheJSON(f.plan)
	return core.Hash(string(raw))
}
func (f *countryCacheFixture) publish() (countryCacheEntry, error) {
	return f.store.publish(context.Background(), f.plan, f.manifest, f.signature, f.download)
}
func requireCountryCacheAbsent(t *testing.T, f *countryCacheFixture) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(f.store.base, countryCacheDatasetID(f.plan))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial data published", err)
	}
}

func TestCountryCacheCompletePublicationAndReuseAreDataOnlyImmutable(t *testing.T) {
	f := newCountryCacheFixture(t)
	entry, err := f.publish()
	if err != nil || !entry.Published || entry.Reused || entry.ActivatedNginxPolicy || entry.Networks != 2 || f.downloads != 2 || entry.OriginalJobID != f.plan.JobID || entry.PlanSHA != f.digest() {
		t.Fatal(entry, err, f.downloads)
	}
	if _, err := os.Lstat(f.stage()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed original stage remained", err)
	}
	before, err := os.Lstat(filepath.Join(f.store.base, entry.Dataset, "CN.cidr"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.publish()
	if err != nil || !reflect.DeepEqual(entry, again) || f.downloads != 2 {
		t.Fatal("same original was replayed", again, err)
	}
	other := f.plan
	other.JobID = core.ID()
	reused, err := f.store.publish(context.Background(), other, f.manifest, f.signature, f.download)
	if err != nil || !reused.Published || !reused.Reused || reused.ActivatedNginxPolicy || reused.OriginalJobID != entry.OriginalJobID || f.downloads != 2 {
		t.Fatal(reused, err)
	}
	after, err := os.Lstat(filepath.Join(f.store.base, entry.Dataset, "CN.cidr"))
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("reuse rewrote immutable asset", err)
	}
	observed, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest())
	if err != nil || !reflect.DeepEqual(observed, entry) || f.downloads != 2 {
		t.Fatal("lost acknowledgement replayed", observed, err)
	}
}

func TestCountryCacheOriginalIDCannotBindAnotherSelectionAfterRename(t *testing.T) {
	f := newCountryCacheFixture(t)
	if _, err := f.publish(); err != nil {
		t.Fatal(err)
	}
	changed := f.plan
	changed.Countries = []string{"US"}
	if got, err := f.store.publish(context.Background(), changed, f.manifest, f.signature, f.download); err == nil || got.Published || f.downloads != 2 {
		t.Fatal("original ID rebound after publication", got, err)
	}
	if _, err := os.Lstat(filepath.Join(f.store.base, countryCacheDatasetID(changed))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("second selection published")
	}
}

func TestCountryCacheEveryInterruptedStageRefusesOrdinaryDownloadReplay(t *testing.T) {
	for _, point := range []string{"after-request.json", "after-manifest.json", "after-manifest.sig", "before-file:CN", "after-file:CN", "before-file:US", "after-file:US", "before-ready", "before-publish", "after-publish"} {
		t.Run(point, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			f.store.fault = func(s string) error {
				if s == point {
					return errors.New("synthetic lost acknowledgement")
				}
				return nil
			}
			if got, err := f.publish(); err == nil || got.Published {
				t.Fatal("injected failure invented outcome", got, err)
			}
			calls := f.downloads
			f.store.fault = nil
			got, err := f.publish()
			if point == "after-publish" {
				if err != nil || !got.Published || got.ActivatedNginxPolicy {
					t.Fatal("original commit not observable", got, err)
				}
			} else {
				requireCountryCacheAbsent(t, f)
				if err == nil || got.Published {
					t.Fatal("partial original silently replayed", got, err)
				}
			}
			if f.downloads != calls {
				t.Fatal("ordinary retry downloaded again")
			}
		})
	}
}

func TestCountryCacheExplicitOriginalFinalizeRequiresAllSignedFilesAndFullDigest(t *testing.T) {
	for _, point := range []string{"after-request.json", "after-manifest.sig", "after-file:CN", "after-file:US", "before-publish"} {
		t.Run(point, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			f.store.fault = func(s string) error {
				if s == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := f.publish(); err == nil {
				t.Fatal("no injected failure")
			}
			f.store.fault = nil
			calls := f.downloads
			for _, pair := range [][2]string{{core.ID(), f.digest()}, {f.plan.JobID, strings.Repeat("a", 64)}, {f.plan.JobID, f.digest()[:32]}} {
				if got, err := f.store.finalize(context.Background(), pair[0], pair[1]); err == nil || got.Published {
					t.Fatal("foreign/partial recovery accepted", got, err)
				}
			}
			got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest())
			complete := point == "after-file:US" || point == "before-publish"
			if complete {
				if err != nil || !got.Published || got.ActivatedNginxPolicy {
					t.Fatal(got, err)
				}
			} else {
				if err == nil || got.Published {
					t.Fatal("incomplete recovery invented files", got, err)
				}
				requireCountryCacheAbsent(t, f)
			}
			if f.downloads != calls {
				t.Fatal("explicit finalize downloaded or replayed network")
			}
		})
	}
}

func TestCountryCacheLostFinalizeAcknowledgementObservesOriginalWithoutAnotherCommit(t *testing.T) {
	f := newCountryCacheFixture(t)
	f.store.fault = func(s string) error {
		if s == "before-ready" {
			return errors.New("interrupt")
		}
		return nil
	}
	if _, err := f.publish(); err == nil {
		t.Fatal("no failure")
	}
	f.store.fault = func(s string) error {
		if s == "after-finalize-publish" {
			return errors.New("lost acknowledgement")
		}
		return nil
	}
	if got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest()); err == nil || got.Published {
		t.Fatal("lost reply invented success", got, err)
	}
	f.store.fault = nil
	got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest())
	if err != nil || !got.Published || got.ActivatedNginxPolicy || f.downloads != 2 {
		t.Fatal(got, err)
	}
}

func TestCountryCacheAtomicCommitCannotReplaceEvenEmptyRacingTarget(t *testing.T) {
	f := newCountryCacheFixture(t)
	f.store.fault = func(s string) error {
		if s == "before-publish" {
			return errors.New("interrupt")
		}
		return nil
	}
	if _, err := f.publish(); err == nil {
		t.Fatal("no failure")
	}
	f.store.fault = nil
	base, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	dir, err := countryCacheDirectory(base, ".country-stage-"+f.plan.JobID)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dataset := countryCacheDatasetID(f.plan)
	if err := base.Mkdir(dataset, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := base.Lstat(dataset)
	if err != nil {
		t.Fatal(err)
	}
	if err := countryCachePublishNoReplace(base, dir, ".country-stage-"+f.plan.JobID, dataset); err == nil {
		t.Fatal("empty target overwritten")
	}
	after, err := base.Lstat(dataset)
	if err != nil || !os.SameFile(identity, after) || !dir.current() {
		t.Fatal("atomic refusal changed original identities", err)
	}
}

func TestCountryCacheCancelledAndRevokedOriginalNeverPublishes(t *testing.T) {
	for _, kind := range []string{"before-open", "during-download", "before-publish", "guard"} {
		t.Run(kind, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "before-open" {
				cancel()
			}
			f.store.fault = func(point string) error {
				if kind == "before-publish" && point == "before-publish" {
					cancel()
				}
				return nil
			}
			if kind == "guard" {
				f.store.guard = func() error { return errors.New("original app authority revoked") }
			}
			download := func(ctx context.Context, a geodata.CountryAuthority, code string, out *os.File) error {
				err := f.download(ctx, a, code, out)
				if kind == "during-download" {
					cancel()
				}
				return err
			}
			got, err := f.store.publish(ctx, f.plan, f.manifest, f.signature, download)
			if err == nil || got.Published || got.ActivatedNginxPolicy {
				t.Fatal(got, err)
			}
			requireCountryCacheAbsent(t, f)
			if (kind == "before-open" || kind == "guard") && f.downloads != 0 {
				t.Fatal("transfer preceded original authority")
			}
		})
	}
}

func TestCountryCacheCallerBuffersCannotChangeBoundPlanOrSignedBytesDuringTransfer(t *testing.T) {
	f := newCountryCacheFixture(t)
	plan := f.plan
	plan.Countries = append([]string(nil), f.plan.Countries...)
	manifest := bytes.Clone(f.manifest)
	signature := bytes.Clone(f.signature)
	download := func(ctx context.Context, a geodata.CountryAuthority, code string, out *os.File) error {
		plan.Countries[0] = "ZZ"
		manifest[0] = '!'
		signature[0] = '!'
		return f.download(ctx, a, code, out)
	}
	got, err := f.store.publish(context.Background(), plan, manifest, signature, download)
	if err != nil || !got.Published || !reflect.DeepEqual(got.Countries, f.plan.Countries) || got.PlanSHA != f.digest() {
		t.Fatal("caller changed private bound input", got, err)
	}
}

func TestCountryCacheIndependentReadbackRejectsTruncatedSwappedOrForeignAssets(t *testing.T) {
	for _, kind := range []string{"truncated", "wrong-country", "extra", "symlink", "hardlink", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			download := func(_ context.Context, _ geodata.CountryAuthority, code string, out *os.File) error {
				payload := f.payload[code]
				if kind == "truncated" {
					payload = payload[:len(payload)-1]
				}
				if kind == "wrong-country" {
					payload = f.payload["US"]
				}
				if kind == "extra" {
					payload = append(bytes.Clone(payload), '\n')
				}
				if _, err := out.Write(payload); err != nil {
					return err
				}
				path := filepath.Join(f.stage(), code+".cidr")
				switch kind {
				case "symlink":
					if err := os.Rename(path, path+".retained"); err != nil {
						return err
					}
					return os.Symlink(path+".retained", path)
				case "hardlink":
					return os.Link(path, path+".retained")
				case "public-mode":
					return out.Chmod(0644)
				}
				return nil
			}
			if got, err := f.store.publish(context.Background(), f.plan, f.manifest, f.signature, download); err == nil || got.Published {
				t.Fatal("unqualified data published", got, err)
			}
			requireCountryCacheAbsent(t, f)
		})
	}
}

func TestCountryCacheReadonlyOrReplacedLockCannotGrantMutation(t *testing.T) {
	f := newCountryCacheFixture(t)
	base, err := f.store.open(true)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	read, err := base.OpenFile("store.lock", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if countryCacheRequireLock(base, read) == nil {
		t.Fatal("readonly descriptor became exclusive mutation authority")
	}
	if countryCacheRequireLock(base, lock) != nil {
		t.Fatal("original lock rejected")
	}
	if err := base.Rename("store.lock", "retained.lock"); err != nil {
		t.Fatal(err)
	}
	if countryCacheRequireLock(base, lock) == nil {
		t.Fatal("unnamed old lock accepted")
	}
}

func TestCountryCacheUnknownRecordUnsafeRootAndCapacityAreNotRepaired(t *testing.T) {
	for _, kind := range []string{"root-mode", "unknown-entry", "too-many-stages", "request-alias"} {
		t.Run(kind, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			base, err := f.store.open(true)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "root-mode":
				if err := os.Chmod(f.store.base, 0755); err != nil {
					t.Fatal(err)
				}
			case "unknown-entry":
				if err := base.Mkdir("foreign-data", 0700); err != nil {
					t.Fatal(err)
				}
			case "too-many-stages":
				for i := 0; i < countryCacheMaxEntries; i++ {
					if err := base.Mkdir(".country-stage-"+core.ID(), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "request-alias":
				name := countryCacheDatasetID(f.plan)
				if err := base.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				d, err := countryCacheDirectory(base, name)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := countryCacheJSON(f.plan)
				raw = bytes.Replace(raw, []byte(`"job_id"`), []byte(`"Job_id"`), 1)
				if err := countryCacheWriteNew(d.Root, "request.json", raw); err != nil {
					t.Fatal(err)
				}
				d.Close()
			}
			base.Close()
			if got, err := f.publish(); err == nil || got.Published || f.downloads != 0 {
				t.Fatal("unsafe state was repaired/adopted", got, err)
			}
			if kind == "root-mode" {
				info, err := os.Lstat(f.store.base)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatal("root permissions repaired", err)
				}
			}
		})
	}
}

func TestCountryCacheExplicitAbortRetainsPartialAndPreparedDataAndPermanentlyStopsOriginal(t *testing.T) {
	for _, point := range []string{"after-request.json", "after-file:CN", "before-ready", "before-publish"} {
		t.Run(point, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			f.store.fault = func(s string) error {
				if s == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := f.publish(); err == nil {
				t.Fatal("no injected failure")
			}
			f.store.fault = nil
			calls := f.downloads
			before := map[string][]byte{}
			identities := map[string]os.FileInfo{}
			entries, err := os.ReadDir(f.stage())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				path := filepath.Join(f.stage(), entry.Name())
				before[entry.Name()], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				identities[entry.Name()], err = os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.abort(context.Background(), f.plan.JobID, strings.Repeat("a", 64)); err == nil {
				t.Fatal("foreign digest aborted original")
			}
			stop, err := f.store.abort(context.Background(), f.plan.JobID, f.digest())
			if err != nil || stop.OriginalJobID != f.plan.JobID || stop.PlanSHA != f.digest() {
				t.Fatal(stop, err)
			}
			again, err := f.store.abort(context.Background(), f.plan.JobID, f.digest())
			if err != nil || again != stop {
				t.Fatal("idempotent stop rewrote receipt", again, err)
			}
			for name, raw := range before {
				path := filepath.Join(f.stage(), name)
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, got) {
					t.Fatal("abort discarded original bytes", name, err)
				}
				info, err := os.Lstat(path)
				if err != nil || !geoStoreStableInfo(identities[name], info) {
					t.Fatal("abort changed original file identity", name, err)
				}
			}
			if got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest()); err == nil || got.Published {
				t.Fatal("aborted prepared stage published", got, err)
			}
			if got, err := f.publish(); err == nil || got.Published || f.downloads != calls {
				t.Fatal("aborted original downloaded again", got, err)
			}
			requireCountryCacheAbsent(t, f)
		})
	}
}

func TestCountryCacheLostAbortAcknowledgementOnlyObservesImmutableOriginalStop(t *testing.T) {
	f := newCountryCacheFixture(t)
	f.store.fault = func(s string) error {
		if s == "after-file:CN" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := f.publish(); err == nil {
		t.Fatal("no injected failure")
	}
	f.store.fault = func(s string) error {
		if s == "after-abort-receipt" {
			return errors.New("lost reply")
		}
		return nil
	}
	if got, err := f.store.abort(context.Background(), f.plan.JobID, f.digest()); err == nil || got.OriginalJobID != "" {
		t.Fatal(got, err)
	}
	f.store.fault = nil
	got, err := f.store.abort(context.Background(), f.plan.JobID, f.digest())
	if err != nil || got.OriginalJobID != f.plan.JobID || f.downloads != 1 {
		t.Fatal(got, err)
	}
	requireCountryCacheAbsent(t, f)
}

func TestCountryCacheCommittedPublicationCannotBeAbortedOrDeleted(t *testing.T) {
	f := newCountryCacheFixture(t)
	entry, err := f.publish()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.abort(context.Background(), f.plan.JobID, f.digest()); err == nil {
		t.Fatal("published data aborted")
	}
	base, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	after, err := f.store.load(context.Background(), base, entry.Dataset)
	if err != nil || !reflect.DeepEqual(entry, after) {
		t.Fatal("abort changed immutable publication", after, err)
	}
}

func TestCountryCacheSignedCrossCountryOverlapCannotPublishOrFinalize(t *testing.T) {
	f := newCountryCacheFixture(t)
	f.payload["CN"] = bytes.Replace(f.payload["CN"], []byte("8.8.4.0/24"), []byte("8.8.8.0/24"), 1)
	var manifest geodata.CountryManifest
	if json.Unmarshal(f.manifest, &manifest) != nil {
		t.Fatal("fixture manifest")
	}
	var assets []geodata.CountryAsset
	if json.Unmarshal([]byte(manifest.AssetsJSON), &assets) != nil {
		t.Fatal("fixture assets")
	}
	manifest.Bytes, manifest.Networks = 0, 0
	for i := range assets {
		metadata, err := geodata.ValidateCountryCIDR(context.Background(), bytes.NewReader(f.payload[assets[i].Code]))
		if err != nil {
			t.Fatal(err)
		}
		assets[i].Bytes, assets[i].Networks, assets[i].SHA256 = metadata.Bytes, metadata.Networks, metadata.SHA256
		manifest.Bytes += metadata.Bytes
		manifest.Networks += metadata.Networks
	}
	raw, _ := json.Marshal(assets)
	manifest.AssetsJSON = string(raw)
	f.manifest, _ = json.Marshal(manifest)
	f.signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, append([]byte(geodata.CountrySignatureDomain), f.manifest...))))
	f.plan.DataManifestSHA = core.Hash(string(f.manifest))
	a, err := geodata.VerifyCountryManifest(f.manifest, f.signature, f.store.trust.PublicKey, f.store.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range f.plan.Countries {
		if _, err := geodata.VerifyCountryAsset(context.Background(), a, code, bytes.NewReader(f.payload[code])); err != nil {
			t.Fatal("fixture is not independently signed-valid", err)
		}
	}
	if got, err := f.publish(); err == nil || got.Published || f.downloads != 2 {
		t.Fatal("ambiguous signed address space published", got, err)
	}
	requireCountryCacheAbsent(t, f)
	if got, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest()); err == nil || got.Published || f.downloads != 2 {
		t.Fatal("explicit recovery adopted ambiguous coverage", got, err)
	}
	if _, err := os.Lstat(filepath.Join(f.stage(), "ready.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ambiguous files received a prepared receipt", err)
	}
}
