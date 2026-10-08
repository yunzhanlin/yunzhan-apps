//go:build linux

package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
	"time"
)

func TestWAFBodyRetentionPlanKeepsLatestAndRejectsUnknownInventory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := core.DefaultWAFBodyLogRetention()
	cfg.Enabled = true
	cfg.ConfirmDelete = true
	cfg.KeepLatest = 1
	entries := []wafBodyLogArchive{}
	for _, id := range []string{"a", "b", "c"} {
		entries = append(entries, wafBodyLogArchive{ID: strings.Repeat(id, 32), CapturedAt: now.Add(-31 * 24 * time.Hour).Format(time.RFC3339), Bytes: 20, SHA256: strings.Repeat("d", 64), State: "completed"})
	}
	plan, err := wafBodyRetentionPlan(&cfg, entries, now)
	if err != nil || len(plan) != 2 || plan[0].ID != entries[1].ID || plan[1].ID != entries[0].ID {
		t.Fatal("latest tie identity not retained", plan, err)
	}
	entries[0].CapturedAt = now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	entries[1].CapturedAt = now.Add(-29 * 24 * time.Hour).Format(time.RFC3339)
	plan, err = wafBodyRetentionPlan(&cfg, entries, now)
	if err != nil || len(plan) != 1 {
		t.Fatal("exact cutoff removed", plan, err)
	}
	for _, state := range []string{"prepared", "copying", "retained", "retained-missing", "removing"} {
		bad := append([]wafBodyLogArchive{}, entries...)
		bad[0].State = state
		if _, err := wafBodyRetentionPlan(&cfg, bad, now); err == nil {
			t.Fatal("unknown inventory accepted", state)
		}
	}
	bad := append([]wafBodyLogArchive{}, entries...)
	bad[0] = bad[1]
	if _, err := wafBodyRetentionPlan(&cfg, bad, now); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	bad = append([]wafBodyLogArchive{}, entries...)
	bad[0].CapturedAt = now.Add(2 * time.Minute).Format(time.RFC3339)
	if _, err := wafBodyRetentionPlan(&cfg, bad, now); err == nil {
		t.Fatal("future clock accepted")
	}
	cfg.Enabled = false
	plan, err = wafBodyRetentionPlan(&cfg, bad, now)
	if err != nil || len(plan) != 0 {
		t.Fatal("disabled policy mutated inventory", plan, err)
	}
}
