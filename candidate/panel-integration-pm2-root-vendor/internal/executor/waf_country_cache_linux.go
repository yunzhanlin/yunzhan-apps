//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

type countryCacheEntry = core.WAFCountryCacheEntry

func countryCacheRequireLock(base *statisticsGeoDirectory, lock *os.File) error {
	if base == nil || lock == nil || !base.current() {
		return errors.New("country cache original lock/root missing")
	}
	flags, err := unix.FcntlInt(lock.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		return errors.New("country cache readonly observation cannot grant mutation")
	}
	opened, err := lock.Stat()
	named, nerr := base.Lstat("store.lock")
	if err != nil || nerr != nil || !moduleRecordInfo(opened, false, false) || !moduleRecordInfo(named, false, false) || opened.Size() != 0 || !geoStoreStableInfo(opened, named) {
		return errors.New("country cache original named lock changed")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("country cache exclusive mutation authority unavailable")
	}
	return nil
}

func (s countryCacheStore) verifyDirectory(ctx context.Context, dir *statisticsGeoDirectory, dataset string, readyRequired bool) (countryCacheEntry, geodata.CountryAuthority, countryCachePlan, error) {
	var empty countryCacheEntry
	var none geodata.CountryAuthority
	var plan countryCachePlan
	if ctx == nil || dir == nil || !dir.current() || !countryDatasetName.MatchString(dataset) || s.trust == nil || s.now == nil {
		return empty, none, plan, errors.New("country cache verification context invalid")
	}
	if err := ctx.Err(); err != nil {
		return empty, none, plan, err
	}
	if _, err := dir.Lstat("abort.json"); !errors.Is(err, os.ErrNotExist) {
		return empty, none, plan, errors.New("country cache original staging was explicitly aborted or abort identity is unknown; no finalize")
	}
	request, requestInfo, err := geoStoreReadIdentity(dir.Root, "request.json", 4096)
	if err != nil || countryCacheDecode(request, &plan) != nil {
		return empty, none, plan, errors.New("country cache original request missing or noncanonical")
	}
	manifest, manifestInfo, err := geoStoreReadIdentity(dir.Root, "manifest.json", geodata.MaxCountryManifestBytes)
	if err != nil {
		return empty, none, plan, err
	}
	signature, signatureInfo, err := geoStoreReadIdentity(dir.Root, "manifest.sig", 128)
	if err != nil {
		return empty, none, plan, err
	}
	a, err := geodata.VerifyCountryManifest(manifest, signature, s.trust.PublicKey, s.now(), nil)
	if err != nil {
		return empty, none, plan, err
	}
	assets, err := countryCachePlanAuthority(plan, a)
	if err != nil || dataset != countryCacheDatasetID(plan) {
		return empty, none, plan, errors.New("country cache name/request differs from exact signed selection")
	}
	entry := countryCacheEntry{Dataset: dataset, DataManifestSHA: a.SHA256(), Countries: append([]string(nil), plan.Countries...), Release: a.Manifest().Release, Revision: a.Manifest().Revision, OriginalJobID: plan.JobID, PlanSHA: core.Hash(string(request))}
	metadata, err := countryCacheVerifySelection(ctx, dir.Root, a, plan.Countries)
	if err != nil {
		return empty, none, plan, err
	}
	for _, asset := range assets {
		entry.Bytes += asset.Bytes
		entry.Networks += asset.Networks
	}
	if metadata.ManifestSHA256 != a.SHA256() || metadata.Bytes != entry.Bytes || metadata.Networks != entry.Networks {
		return empty, none, plan, errors.New("country cache joint selection differs from complete signed inventory")
	}
	if err := countryCacheExactContents(dir.Root, countryCacheExpectedNames(plan, readyRequired)); err != nil {
		return empty, none, plan, err
	}
	if readyRequired {
		raw, err := geoStoreRead(dir.Root, "ready.json", 4096)
		if err != nil {
			return empty, none, plan, err
		}
		var ready countryCacheReady
		if countryCacheDecode(raw, &ready) != nil || ready.Format != 1 || ready.Dataset != dataset || ready.OriginalJobID != plan.JobID || ready.PlanSHA != entry.PlanSHA || !hardeningCanonicalTime(ready.PreparedAt) {
			return empty, none, plan, errors.New("country cache original prepared receipt conflicts")
		}
		entry.PreparedAt = ready.PreparedAt
	}
	for _, file := range []struct {
		name string
		info os.FileInfo
	}{{"request.json", requestInfo}, {"manifest.json", manifestInfo}, {"manifest.sig", signatureInfo}} {
		current, err := dir.Lstat(file.name)
		if err != nil || !moduleRecordInfo(current, false, false) || !geoStoreStableInfo(file.info, current) {
			return empty, none, plan, errors.New("country cache original signed metadata changed during joint verification")
		}
	}
	if !dir.current() || ctx.Err() != nil {
		return empty, none, plan, errors.New("country cache changed or cancelled before complete acceptance")
	}
	return entry, a, plan, nil
}

func (s countryCacheStore) load(ctx context.Context, base *statisticsGeoDirectory, dataset string) (countryCacheEntry, error) {
	entry, _, err := s.loadAuthority(ctx, base, dataset)
	return entry, err
}

func (s countryCacheStore) loadAuthority(ctx context.Context, base *statisticsGeoDirectory, dataset string) (countryCacheEntry, geodata.CountryAuthority, error) {
	var empty countryCacheEntry
	var none geodata.CountryAuthority
	if !countryDatasetName.MatchString(dataset) {
		return empty, none, errors.New("country cache published dataset ID invalid")
	}
	dir, err := countryCacheDirectory(base, dataset)
	if err != nil {
		return empty, none, err
	}
	defer dir.Close()
	entry, authority, _, err := s.verifyDirectory(ctx, dir, dataset, true)
	if err != nil {
		return empty, none, err
	}
	if !base.current() {
		return empty, none, errors.New("country cache original root changed")
	}
	entry.Published = true
	return entry, authority, nil
}

// This primitive publishes ONLY independently signed immutable PUBLIC DATA.
// The upper app/job controller must independently bind its full app envelope,
// actor, original queue ID and payload. The callback is internal Go code, never
// a URL/command/request verification flag. No Nginx selector/service is changed.
func (s countryCacheStore) publish(ctx context.Context, plan countryCachePlan, manifest, signature []byte, download func(context.Context, geodata.CountryAuthority, string, *os.File) error) (countryCacheEntry, error) {
	var empty countryCacheEntry
	if ctx == nil || s.trust == nil || s.now == nil || download == nil || len(manifest) < 1 || len(manifest) > geodata.MaxCountryManifestBytes || len(signature) < 1 || len(signature) > 128 || len(plan.Countries) < 1 || len(plan.Countries) > 32 {
		return empty, errors.New("country cache publisher environment missing")
	}
	manifest, signature = bytes.Clone(manifest), bytes.Clone(signature)
	plan.Countries = append([]string(nil), plan.Countries...)
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	a, err := geodata.VerifyCountryManifest(manifest, signature, s.trust.PublicKey, s.now(), nil)
	if err != nil {
		return empty, err
	}
	assets, err := countryCachePlanAuthority(plan, a)
	if err != nil {
		return empty, err
	}
	request, err := countryCacheJSON(plan)
	if err != nil || len(request) > 4096 {
		return empty, errors.New("country cache original request capacity invalid")
	}
	if err := s.checkpoint("before-open"); err != nil {
		return empty, err
	}
	base, err := s.open(true)
	if err != nil {
		return empty, err
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	dataset := countryCacheDatasetID(plan)
	if err := s.originalBinding(ctx, base, plan.JobID, core.Hash(string(request)), dataset); err != nil {
		return empty, err
	}
	if _, err := base.Lstat(dataset); err == nil {
		entry, err := s.load(ctx, base, dataset)
		if err != nil {
			return empty, err
		}
		if entry.DataManifestSHA != plan.DataManifestSHA || !reflect.DeepEqual(entry.Countries, plan.Countries) {
			return empty, errors.New("country cache existing publication differs")
		}
		if entry.OriginalJobID == plan.JobID && entry.PlanSHA != core.Hash(string(request)) {
			return empty, errors.New("country cache original job already binds different plan")
		}
		entry.Reused = entry.OriginalJobID != plan.JobID
		return entry, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	stageName := ".country-stage-" + plan.JobID
	if _, err := base.Lstat(stageName); !errors.Is(err, os.ErrNotExist) {
		return empty, errors.New("country cache original staging exists; inspect original ID/full digest, no replay or download")
	}
	used, count, err := s.usage(ctx, base)
	if err != nil {
		return empty, err
	}
	needed := int64(len(manifest) + len(signature) + len(request) + 4096)
	for _, asset := range assets {
		needed += asset.Bytes
	}
	if count >= countryCacheMaxEntries || needed > countryCacheMaxBytes-used {
		return empty, errors.New("country cache quota unavailable; no old data pruned or overwritten")
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, err
	}
	if err := s.checkpoint("before-stage"); err != nil {
		return empty, err
	}
	if err := base.Mkdir(stageName, 0700); err != nil {
		return empty, err
	}
	if err := hardeningJournalSync(base.Root); err != nil {
		return empty, err
	}
	dir, err := countryCacheDirectory(base, stageName)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	// Original complete plan is durable before ANY source file transfer.
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"request.json", request}, {"manifest.json", manifest}, {"manifest.sig", signature}} {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if err := countryCacheWriteNew(dir.Root, file.name, file.raw); err != nil {
			return empty, err
		}
		if err := s.checkpoint("after-" + file.name); err != nil {
			return empty, err
		}
	}
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if !dir.current() || countryCacheRequireLock(base, lock) != nil {
			return empty, errors.New("country cache original lock/staging identity changed")
		}
		if err := s.checkpoint("before-file:" + asset.Code); err != nil {
			return empty, err
		}
		f, err := dir.OpenFile(asset.Code+".cidr", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
		if err != nil {
			return empty, err
		}
		err = download(ctx, a, asset.Code, f)
		if err == nil {
			err = f.Sync()
		}
		closed := f.Close()
		if err != nil {
			return empty, err
		}
		if closed != nil {
			return empty, closed
		}
		if err := countryCacheVerifyFile(ctx, dir.Root, a, asset); err != nil {
			return empty, err
		}
		if err := s.checkpoint("after-file:" + asset.Code); err != nil {
			return empty, err
		}
	}
	if _, _, _, err := s.verifyDirectory(ctx, dir, dataset, false); err != nil {
		return empty, err
	}
	if err := s.checkpoint("before-ready"); err != nil {
		return empty, err
	}
	ready := countryCacheReady{Format: 1, Dataset: dataset, OriginalJobID: plan.JobID, PlanSHA: core.Hash(string(request)), PreparedAt: s.now().UTC().Format(time.RFC3339)}
	raw, err := countryCacheJSON(ready)
	if err != nil {
		return empty, err
	}
	if err := countryCacheWriteNew(dir.Root, "ready.json", raw); err != nil {
		return empty, err
	}
	if _, _, _, err := s.verifyDirectory(ctx, dir, dataset, true); err != nil {
		return empty, err
	}
	if err := s.checkpoint("before-publish"); err != nil {
		return empty, err
	}
	check, release, err := s.publicationLease(ctx)
	if err != nil {
		return empty, err
	}
	defer release()
	if err := check(); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, err
	}
	if !dir.current() {
		return empty, errors.New("country cache staging changed before immutable publish")
	}
	if _, err := base.Lstat(dataset); !errors.Is(err, os.ErrNotExist) {
		return empty, errors.New("country cache target appeared; no publication overwrite")
	}
	// Sole commit point. Immutable prepared proof moves WITH the exact data.
	if err := check(); err != nil {
		return empty, err
	}
	if err := countryCachePublishNoReplace(base, dir, stageName, dataset); err != nil {
		return empty, err
	}
	if err := hardeningJournalSync(base.Root); err != nil {
		return empty, err
	}
	if err := s.checkpoint("after-publish"); err != nil {
		return empty, err
	}
	return s.load(ctx, base, dataset)
}
