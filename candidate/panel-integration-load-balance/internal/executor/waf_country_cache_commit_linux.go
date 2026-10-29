//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Publication never replaces even an empty racing directory. No fallback to a
// prechecked plain rename is permitted on a filesystem lacking NOREPLACE.
func countryCachePublishNoReplace(base, dir *statisticsGeoDirectory, stage, dataset string) error {
	if base == nil || dir == nil || !base.current() || !dir.current() || !countryStageName.MatchString(stage) || !countryDatasetName.MatchString(dataset) {
		return errors.New("country cache immutable commit anchors invalid")
	}
	named, err := base.Lstat(stage)
	if err != nil || !os.SameFile(named, dir.identity) || !moduleRecordInfo(named, true, false) {
		return errors.New("country cache original staging name changed")
	}
	f, err := base.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, base.identity) || !base.current() || !dir.current() {
		return errors.New("country cache commit directory changed")
	}
	return unix.Renameat2(int(f.Fd()), stage, int(f.Fd()), dataset, unix.RENAME_NOREPLACE)
}

// A completed rename must not erase the original task's identity. The bounded
// metadata scan also catches attempts to reuse that ID for another selection.
func (s countryCacheStore) originalBinding(ctx context.Context, base *statisticsGeoDirectory, id, planSHA, dataset string) error {
	if ctx == nil || !core.ValidID(id) || !countryDatasetName.MatchString(dataset) || !base.current() {
		return errors.New("country cache original identity binding missing")
	}
	f, err := base.Open(".")
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(countryCacheMaxEntries + 2)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > countryCacheMaxEntries+1 {
		return errors.New("country cache original inventory exceeds fixed capacity")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name() == "store.lock" || countryStageName.MatchString(entry.Name()) {
			continue
		}
		dir, err := countryCacheDirectory(base, entry.Name())
		if err != nil {
			return err
		}
		raw, err := geoStoreRead(dir.Root, "request.json", 4096)
		var plan countryCachePlan
		if err == nil {
			err = countryCacheDecode(raw, &plan)
		}
		var ready countryCacheReady
		if err == nil {
			var proof []byte
			proof, err = geoStoreRead(dir.Root, "ready.json", 4096)
			if err == nil {
				err = countryCacheDecode(proof, &ready)
			}
		}
		current := dir.current()
		dir.Close()
		if err != nil || !current || !countryCacheValidPlan(plan) || entry.Name() != countryCacheDatasetID(plan) || ready.Format != 1 || ready.Dataset != entry.Name() || ready.OriginalJobID != plan.JobID || ready.PlanSHA != core.Hash(string(raw)) || !hardeningCanonicalTime(ready.PreparedAt) {
			return errors.New("country cache published original identity evidence invalid")
		}
		if plan.JobID == id && (entry.Name() != dataset || ready.PlanSHA != planSHA) {
			return errors.New("country cache original task already published a different complete plan")
		}
	}
	if !base.current() {
		return errors.New("country cache original root changed during binding")
	}
	return nil
}

// Explicit recovery is bound to the ORIGINAL ID and COMPLETE canonical plan
// digest. It never downloads or repairs a file. Only a fully present, signed,
// independently reread data set can cross the original atomic commit point.
func (s countryCacheStore) finalize(ctx context.Context, id, planSHA string) (countryCacheEntry, error) {
	var empty countryCacheEntry
	if ctx == nil || !core.ValidID(id) || !wafLogDigestValid(planSHA) || ctx.Err() != nil {
		return empty, errors.New("country cache explicit original recovery identity invalid")
	}
	if err := s.checkpoint("before-finalize-open"); err != nil {
		return empty, err
	}
	base, err := s.open(false)
	if err != nil {
		return empty, err
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	stage := ".country-stage-" + id
	dir, err := countryCacheDirectory(base, stage)
	if err != nil {
		// Unknown acknowledgement after rename is observed, never replayed.
		if !errors.Is(err, os.ErrNotExist) {
			return empty, err
		}
		return s.findOriginalPublished(ctx, base, id, planSHA)
	}
	defer dir.Close()
	raw, err := geoStoreRead(dir.Root, "request.json", 4096)
	var plan countryCachePlan
	if err != nil || countryCacheDecode(raw, &plan) != nil || plan.JobID != id || core.Hash(string(raw)) != planSHA {
		return empty, errors.New("country cache recovery complete original plan differs")
	}
	dataset := countryCacheDatasetID(plan)
	if err := s.originalBinding(ctx, base, id, planSHA, dataset); err != nil {
		return empty, err
	}
	if _, _, err := s.usage(ctx, base); err != nil {
		return empty, err
	}
	_, readyErr := dir.Lstat("ready.json")
	if errors.Is(readyErr, os.ErrNotExist) {
		if _, _, _, err := s.verifyDirectory(ctx, dir, dataset, false); err != nil {
			return empty, err
		}
		if err := s.checkpoint("before-finalize-ready"); err != nil {
			return empty, err
		}
		ready := countryCacheReady{1, dataset, id, planSHA, s.now().UTC().Format(time.RFC3339)}
		encoded, err := countryCacheJSON(ready)
		if err != nil {
			return empty, err
		}
		if err := countryCacheRequireLock(base, lock); err != nil {
			return empty, err
		}
		if err := countryCacheWriteNew(dir.Root, "ready.json", encoded); err != nil {
			return empty, err
		}
	} else if readyErr != nil {
		return empty, readyErr
	}
	if _, _, _, err := s.verifyDirectory(ctx, dir, dataset, true); err != nil {
		return empty, err
	}
	if err := s.checkpoint("before-finalize-publish"); err != nil {
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
	if err := check(); err != nil {
		return empty, err
	}
	if err := countryCachePublishNoReplace(base, dir, stage, dataset); err != nil {
		return empty, err
	}
	if err := hardeningJournalSync(base.Root); err != nil {
		return empty, err
	}
	if err := s.checkpoint("after-finalize-publish"); err != nil {
		return empty, err
	}
	return s.load(ctx, base, dataset)
}

func (s countryCacheStore) findOriginalPublished(ctx context.Context, base *statisticsGeoDirectory, id, planSHA string) (countryCacheEntry, error) {
	var empty countryCacheEntry
	f, err := base.Open(".")
	if err != nil {
		return empty, err
	}
	entries, err := f.ReadDir(countryCacheMaxEntries + 2)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > countryCacheMaxEntries+1 {
		return empty, errors.New("country cache original observation capacity exceeded")
	}
	var found countryCacheEntry
	for _, e := range entries {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		if e.Name() == "store.lock" || countryStageName.MatchString(e.Name()) {
			continue
		}
		entry, err := s.load(ctx, base, e.Name())
		if err != nil {
			return empty, err
		}
		if entry.OriginalJobID == id {
			if entry.PlanSHA != planSHA || found.Dataset != "" {
				return empty, errors.New("country cache original publication identity conflicts")
			}
			found = entry
		}
	}
	if found.Dataset == "" {
		return empty, errors.New("country cache original complete publication not found; no replay")
	}
	return found, nil
}
