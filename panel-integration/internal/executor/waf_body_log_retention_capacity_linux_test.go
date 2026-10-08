//go:build linux

package executor

import (
	"bytes"
	"context"
	"local/panel/internal/core"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWAFBodyRetentionUnknownHistoryCapacityStopsBeforeAnyNewDeletion(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	out, err := runRetentionFixture(t, s, cfg, now, nil)
	if err != nil || out.Operation == nil {
		t.Fatal("missing original completed plan", err)
	}
	out.Operation.State = "retained_unknown"
	for i := 0; i < wafBodyRetentionHistoryLimit; i++ {
		item := *out.Operation
		item.Plan.ID = core.ID()
		item.PlanSHA256 = retentionPlanSHA(item.Plan)
		out.History = append(out.History, item)
	}
	if err := s.writeWAFBodyRetentionRecord(out); err != nil {
		t.Fatal(err)
	}
	// Historical uncertain plans here refer only to absent snapshots. This
	// isolates the bounded-history guard from the surviving-artifact guard.
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(path, row, 0640); err != nil {
			t.Fatal(err)
		}
		entry, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		entry.CapturedAt = now.Add(-time.Duration(42-i) * 24 * time.Hour).Format(time.RFC3339)
		if err := s.writeWAFBodyLogIndex(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, row, 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.wafBodyRetentionPath())
	inventory, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = runRetentionFixture(t, s, cfg, now.Add(time.Minute), func(string) error { t.Fatal("full unknown history started deletion"); return nil })
	if err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatal("unknown evidence discarded to make room")
	}
	after, _ := os.ReadFile(s.wafBodyRetentionPath())
	live, _ := os.ReadFile(path)
	remaining, e := s.wafBodyRetentionInventory(context.Background())
	if e != nil || !bytes.Equal(before, after) || !bytes.Equal(live, row) || !reflect.DeepEqual(inventory, remaining) {
		t.Fatal("full history changed evidence or logs", e)
	}
}

func TestWAFBodyRetentionHistoryOnlyEvictsCompletedSummary(t *testing.T) {
	s, _, _, cfg, now := retentionFixture(t)
	out, err := runRetentionFixture(t, s, cfg, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < wafBodyRetentionHistoryLimit; i++ {
		item := *out.Operation
		item.Plan.ID = core.ID()
		item.PlanSHA256 = retentionPlanSHA(item.Plan)
		item.State = "retained_unknown"
		if i == 7 {
			item.State = "completed"
		}
		out.History = append(out.History, item)
	}
	original := append([]wafBodyRetentionOperation{}, out.History...)
	if err := archiveWAFRetentionOperation(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.History) != wafBodyRetentionHistoryLimit || out.History[len(out.History)-1].Plan.ID != out.Operation.Plan.ID {
		t.Fatal("capacity or current summary lost")
	}
	for _, old := range original {
		found := false
		for _, current := range out.History {
			found = found || reflect.DeepEqual(old, current)
		}
		if found != (old.State == "retained_unknown") {
			t.Fatal("unknown summary evicted or completed summary not evicted")
		}
	}
	if err := validateWAFRetentionOperation(*out.Operation); err != nil {
		t.Fatal(err)
	}
	forged := *out.Operation
	forged.Plan.Selected = append([]string{}, forged.Plan.Selected...)
	forged.Plan.Selected[0] = forged.Plan.Inventory[0].Archive.ID
	forged.Deleted = append([]string{}, forged.Plan.Selected...)
	forged.PlanSHA256 = retentionPlanSHA(forged.Plan)
	if err := validateWAFRetentionOperation(forged); err == nil {
		t.Fatal("rehashed plan selected protected latest snapshot")
	}
}
