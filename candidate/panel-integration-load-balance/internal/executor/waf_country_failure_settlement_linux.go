//go:build linux

package executor

import (
	"context"
	"errors"
	"os"

	"local/panel/internal/core"
)

// Only the ORIGINAL still-running worker calls this while holding its task
// lock. It never fetches, promotes prepared data, overwrites a terminal result,
// or retries publish. Committed data is re-read; uncommitted partial bytes may
// only receive an append-only abort seal under the current original guard.
func (s countryCacheStore) settlePublicationError(ctx context.Context, plan countryCachePlan) (string, *countryCacheEntry, error) {
	unknown := func(err error) (string, *countryCacheEntry, error) { return "needs_attention", nil, err }
	if ctx == nil || ctx.Err() != nil || !countryCacheValidPlan(plan) {
		return unknown(errors.New("原地域发布结果缺少可用上下文或完整身份"))
	}
	raw, err := countryCacheJSON(plan)
	if err != nil {
		return unknown(err)
	}
	planSHA, dataset := core.Hash(string(raw)), countryCacheDatasetID(plan)
	base, err := s.open(false)
	if err != nil {
		return unknown(err)
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return unknown(err)
	}
	locked := true
	defer func() {
		if locked {
			lock.Close()
		}
	}()
	if err := s.originalBinding(ctx, base, plan.JobID, planSHA, dataset); err != nil {
		return unknown(err)
	}
	if _, _, err := s.usage(ctx, base); err != nil {
		return unknown(err)
	}
	if _, err := base.Lstat(dataset); err == nil {
		entry, err := s.load(ctx, base, dataset)
		if err != nil {
			return unknown(err)
		}
		if entry.OriginalJobID != plan.JobID || entry.PlanSHA != planSHA {
			return unknown(errors.New("发布目录属于另一原任务，未采用其成功结果"))
		}
		return "succeeded", &entry, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return unknown(err)
	}
	stage := ".country-stage-" + plan.JobID
	if _, err := base.Lstat(stage); errors.Is(err, os.ErrNotExist) {
		// Under the original exclusive cache lock, neither original staging nor
		// publication exists. No cleanup or download is needed or permitted.
		if !base.current() || ctx.Err() != nil {
			return unknown(errors.New("原地域无提交结果的观察已失效"))
		}
		if err := s.checkpoint("before-failed-publication-observation"); err != nil {
			return unknown(err)
		}
		return "failed", nil, nil
	} else if err != nil {
		return unknown(err)
	}
	lock.Close()
	locked = false
	// abort reopens and rechecks exact original plan, absence of publication,
	// directory identity, quota, current guard and exclusive lock before append.
	stop, err := s.abort(ctx, plan.JobID, planSHA)
	if err != nil || stop.OriginalJobID != plan.JobID || stop.PlanSHA != planSHA {
		if err == nil {
			err = errors.New("原地域未提交收尾回执无法核对")
		}
		return unknown(err)
	}
	return "failed", nil, nil
}
