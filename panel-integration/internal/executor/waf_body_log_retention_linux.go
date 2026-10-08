//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"sort"
	"time"
)

// Build the entire deletion plan before touching a snapshot. Unknown outcomes
// block the cycle rather than being filtered into a misleading empty plan.
func wafBodyRetentionPlan(cfg *core.WAFBodyLogRetentionConfig, archives []wafBodyLogArchive, now time.Time) ([]wafBodyLogArchive, error) {
	out := []wafBodyLogArchive{}
	if err := core.ValidateWAFBodyLogRetention(cfg); err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.Enabled {
		return out, nil
	}
	if len(archives) > wafBodyLogArchiveLimit {
		return nil, errors.New("快照库存超过固定上限，未自动清理")
	}
	ordered := append([]wafBodyLogArchive{}, archives...)
	seen := map[string]bool{}
	for _, entry := range ordered {
		if entry.State != "completed" || !validWAFRotationArchive(&entry) || seen[entry.ID] {
			return nil, errors.New("快照包含未知结果、重复身份或异常记录，未自动清理")
		}
		seen[entry.ID] = true
		at, _ := time.Parse(time.RFC3339, entry.CapturedAt)
		if at.After(now.Add(time.Minute)) {
			return nil, errors.New("快照时间位于未来，未自动清理")
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].CapturedAt == ordered[j].CapturedAt {
			return ordered[i].ID > ordered[j].ID
		}
		return ordered[i].CapturedAt > ordered[j].CapturedAt
	})
	cutoff := now.UTC().Add(-time.Duration(cfg.Days) * 24 * time.Hour)
	for i, entry := range ordered {
		at, _ := time.Parse(time.RFC3339, entry.CapturedAt)
		if i >= cfg.KeepLatest && at.Before(cutoff) {
			out = append(out, entry)
		}
	}
	return out, nil
}
