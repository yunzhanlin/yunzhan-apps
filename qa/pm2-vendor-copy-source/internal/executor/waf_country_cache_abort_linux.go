//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"time"

	"local/panel/internal/core"
)

// Explicit original-ID/full-digest abort retains EVERY original byte. It only
// appends an immutable stop receipt to private incomplete staging. The original
// ID can never download again and finalize can never publish the aborted data.
// No quota pruning, active policy, service or software installation is changed.
func (s countryCacheStore) abort(ctx context.Context, id, planSHA string) (countryCacheAborted, error) {
	var empty countryCacheAborted
	if ctx == nil || ctx.Err() != nil || !core.ValidID(id) || !wafLogDigestValid(planSHA) {
		return empty, errors.New("country cache abort requires complete original identity")
	}
	if err := s.checkpoint("before-abort-open"); err != nil {
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
	dir, err := countryCacheDirectory(base, ".country-stage-"+id)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	raw, err := geoStoreRead(dir.Root, "request.json", 4096)
	var plan countryCachePlan
	if err != nil || countryCacheDecode(raw, &plan) != nil || !countryCacheValidPlan(plan) || plan.JobID != id || core.Hash(string(raw)) != planSHA {
		return empty, errors.New("country cache abort original request/digest differs")
	}
	if err := s.originalBinding(ctx, base, id, planSHA, countryCacheDatasetID(plan)); err != nil {
		return empty, err
	}
	if _, err := base.Lstat(countryCacheDatasetID(plan)); !errors.Is(err, os.ErrNotExist) {
		return empty, errors.New("country cache published data cannot be aborted")
	}
	used, _, err := s.usage(ctx, base)
	if err != nil {
		return empty, err
	}
	if prior, err := geoStoreRead(dir.Root, "abort.json", 4096); err == nil {
		var stop countryCacheAborted
		if countryCacheDecode(prior, &stop) != nil || stop.Format != 1 || stop.OriginalJobID != id || stop.PlanSHA != planSHA || !hardeningCanonicalTime(stop.AbortedAt) {
			return empty, errors.New("country cache original stop receipt differs")
		}
		return stop, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	if err := s.checkpoint("before-abort-receipt"); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, err
	}
	if !dir.current() {
		return empty, errors.New("country cache original abort staging changed")
	}
	stop := countryCacheAborted{1, id, planSHA, s.now().UTC().Format(time.RFC3339)}
	receipt, err := countryCacheJSON(stop)
	if err != nil {
		return empty, err
	}
	if int64(len(receipt)) > countryCacheMaxBytes-used {
		return empty, errors.New("country cache stop receipt quota unavailable; original bytes retained")
	}
	if err := countryCacheWriteNew(dir.Root, "abort.json", receipt); err != nil {
		return empty, err
	}
	if err := s.checkpoint("after-abort-receipt"); err != nil {
		return empty, err
	}
	return stop, nil
}
