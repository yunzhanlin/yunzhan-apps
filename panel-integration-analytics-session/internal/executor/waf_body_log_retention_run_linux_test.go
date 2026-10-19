//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func retentionFixture(t *testing.T) (*Service, string, []byte, core.WAFConfig, time.Time) {
	t.Helper()
	s, path, row := wafBodyLogFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, row, 0640); err != nil {
			t.Fatal(err)
		}
		entry, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		entry.CapturedAt = now.Add(-time.Duration(40-i) * 24 * time.Hour).Format(time.RFC3339)
		if err := s.writeWAFBodyLogIndex(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, row, 0640); err != nil {
		t.Fatal(err)
	}
	cfg := wafRotationTestConfig()
	cfg.BodyLogRotation = nil
	cfg.BodyLogRetention = &core.WAFBodyLogRetentionConfig{Enabled: true, ConfirmDelete: true, Days: 30, KeepLatest: 1}
	return s, path, row, cfg, now
}

func runRetentionFixture(t *testing.T, s *Service, cfg core.WAFConfig, now time.Time, checkpoint func(string) error) (wafBodyRetentionRecord, error) {
	t.Helper()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	return s.runWAFBodyRetentionLocked(context.Background(), now, lock, cfg, checkpoint)
}

func TestWAFBodyRetentionDeletesOnlyExpiredCompletedCopiesAndPersistsProgress(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	before, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil || len(before) != 3 {
		t.Fatal(before, err)
	}
	liveInfo, _ := os.Stat(path)
	result, err := runRetentionFixture(t, s, cfg, now, nil)
	if err != nil || result.Operation == nil || result.Operation.State != "completed" || len(result.Operation.Deleted) != 2 {
		t.Fatal(result, err)
	}
	after, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil || len(after) != 1 || after[0] != before[0] {
		t.Fatal("latest snapshot changed", after, err)
	}
	live, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if !bytes.Equal(live, row) || !os.SameFile(liveInfo, info) {
		t.Fatal("retention changed current log")
	}
	first, _, err := s.readWAFBodyRetentionRecord()
	if err != nil || first.Operation.PlanSHA256 != result.Operation.PlanSHA256 {
		t.Fatal(first, err)
	}
	second, err := runRetentionFixture(t, New(s.Config), cfg, now.Add(time.Minute), func(string) error { t.Fatal("completed plan repeated deletion"); return nil })
	if err != nil || second.Operation.Plan.ID != first.Operation.Plan.ID || len(second.History) != 0 {
		t.Fatal(second, err)
	}
}

func TestWAFBodyRetentionFiveInterruptionsRetainUnknownAndNeverAutomaticallyRetry(t *testing.T) {
	for _, cut := range []string{"retention-intent-durable", "remove-intent-durable", "snapshot-unlink-durable", "retention-snapshot-removed", "retention-progress-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, row, cfg, now := retentionFixture(t)
			hit := false
			out, err := runRetentionFixture(t, s, cfg, now, func(stage string) error {
				if stage == cut {
					hit = true
					return errors.New("owned interruption")
				}
				return nil
			})
			if !hit || err == nil || out.Operation == nil || out.Operation.State != "unknown" {
				t.Fatal(out, err)
			}
			record, _ := os.ReadFile(s.wafBodyRetentionPath())
			_, err = runRetentionFixture(t, New(s.Config), cfg, now.Add(time.Minute), func(string) error { t.Fatal("unknown operation repeated deletion"); return nil })
			if err == nil {
				t.Fatal("unknown result accepted")
			}
			current, _ := os.ReadFile(s.wafBodyRetentionPath())
			live, _ := os.ReadFile(path)
			if !bytes.Equal(current, record) || !bytes.Equal(live, row) {
				t.Fatal("unknown evidence or live log changed")
			}
			_, sha, err := s.readWAFBodyRetentionRecord()
			if err != nil {
				t.Fatal(err)
			}
			retained, err := s.retainWAFBodyRetentionOutcome(context.Background(), sha, now.Add(time.Minute))
			if err != nil || retained.Operation.State != "retained_unknown" || retained.Operation.PlanSHA256 != out.Operation.PlanSHA256 || len(retained.Operation.Deleted) != len(out.Operation.Deleted) {
				t.Fatal("uncertainty converted to success", retained, err)
			}
			if _, err := s.retainWAFBodyRetentionOutcome(context.Background(), sha, now.Add(time.Minute)); err == nil {
				t.Fatal("stale review digest reused")
			}
			preserved, err := s.wafRetainedUnknownArchiveIDs(context.Background(), retained)
			if err != nil || len(preserved) == 0 {
				t.Fatal("remaining original evidence not protected", preserved, err)
			}
			reviewedBytes, _ := os.ReadFile(s.wafBodyRetentionPath())
			_, err = runRetentionFixture(t, New(s.Config), cfg, now.Add(2*time.Minute), func(string) error { t.Fatal("reviewed interrupted plan reentered deletion"); return nil })
			if err == nil {
				t.Fatal("review lifted residual-evidence pause")
			}
			afterReview, _ := os.ReadFile(s.wafBodyRetentionPath())
			live, _ = os.ReadFile(path)
			if !bytes.Equal(afterReview, reviewedBytes) || !bytes.Equal(live, row) {
				t.Fatal("reviewed unknown plan changed")
			}
		})
	}
}

func TestWAFBodyRetentionOpenWritableSnapshotRefusesAndPreservesLiveLog(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	inventory, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	selected := inventory[1].Archive
	f, err := os.OpenFile(filepath.Join(s.wafBodyLogArchiveDirectory(), selected.ID+".log"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := runRetentionFixture(t, s, cfg, now, nil)
	if err == nil || out.Operation == nil || out.Operation.State != "unknown" || len(out.Operation.Deleted) != 0 {
		t.Fatal("writable snapshot was removed", out, err)
	}
	live, _ := os.ReadFile(path)
	if !bytes.Equal(live, row) {
		t.Fatal("writer refusal changed live log")
	}
	if _, err := os.Lstat(filepath.Join(s.wafBodyLogArchiveDirectory(), selected.ID+".log")); err != nil {
		t.Fatal("writable snapshot missing", err)
	}
}

func TestWAFBodyRetentionSnapshotReplacementAfterIntentNeverUnlinksReplacement(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	changed := ""
	replacement := []byte("owned replacement must remain")
	out, err := runRetentionFixture(t, s, cfg, now, func(stage string) error {
		if stage != "remove-intent-durable" || changed != "" {
			return nil
		}
		pending, e := s.wafBodyLogRecoveryEntries(context.Background())
		if e != nil || len(pending) != 1 {
			t.Fatal(pending, e)
		}
		changed = filepath.Join(s.wafBodyLogArchiveDirectory(), pending[0].Archive.ID+".log")
		if e := os.Rename(changed, filepath.Join(t.TempDir(), "original-evidence")); e != nil {
			t.Fatal(e)
		}
		return os.WriteFile(changed, replacement, 0600)
	})
	if err == nil || changed == "" || out.Operation.State != "unknown" {
		t.Fatal(out, err)
	}
	actual, _ := os.ReadFile(changed)
	live, _ := os.ReadFile(path)
	if !bytes.Equal(actual, replacement) || !bytes.Equal(live, row) {
		t.Fatal("replacement or live log removed")
	}
}
