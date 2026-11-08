//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWAFBodyRetentionReviewedUnknownNeverReentersFutureDeletionPlans(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	out, err := runRetentionFixture(t, s, cfg, now, func(stage string) error {
		if stage == "retention-intent-durable" {
			return errors.New("owned interruption before any deletion")
		}
		return nil
	})
	if err == nil || out.Operation == nil || out.Operation.State != "unknown" || len(out.Operation.Deleted) != 0 {
		t.Fatal(out, err)
	}
	before, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, sha, err := s.readWAFBodyRetentionRecord()
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := s.retainWAFBodyRetentionOutcome(context.Background(), sha, now.Add(time.Minute))
	if err != nil || reviewed.Operation.State != "retained_unknown" {
		t.Fatal(reviewed, err)
	}
	saved, err := os.ReadFile(s.wafBodyRetentionPath())
	if err != nil {
		t.Fatal(err)
	}
	entered := false
	_, err = runRetentionFixture(t, New(s.Config), cfg, now.Add(2*time.Minute), func(string) error {
		entered = true
		return errors.New("test refuses to execute a new deletion for the reviewed unknown snapshots")
	})
	if entered || err == nil {
		t.Fatal("reviewed unknown snapshots were selected by a new automatic deletion plan", err)
	}
	after, err := s.wafBodyRetentionInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(s.wafBodyRetentionPath())
	live, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) || !bytes.Equal(saved, actual) || !bytes.Equal(live, row) {
		t.Fatal("reviewed unknown evidence or current log changed")
	}
}

func reviewedRetentionFixture(t *testing.T, history bool) (*Service, string, []byte, core.WAFConfig, time.Time, wafBodyRetentionRecord, []byte) {
	t.Helper()
	s, path, row, cfg, now := retentionFixture(t)
	out, err := runRetentionFixture(t, s, cfg, now, func(stage string) error {
		if stage == "retention-intent-durable" {
			return errors.New("owned interruption before any deletion")
		}
		return nil
	})
	if err == nil || out.Operation == nil || out.Operation.State != "unknown" {
		t.Fatal(out, err)
	}
	_, sha, err := s.readWAFBodyRetentionRecord()
	if err != nil {
		t.Fatal(err)
	}
	out, err = s.retainWAFBodyRetentionOutcome(context.Background(), sha, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if history {
		out.History = append(out.History, *out.Operation)
		out.Operation = nil
		if err := s.writeWAFBodyRetentionRecord(out); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := os.ReadFile(s.wafBodyRetentionPath())
	if err != nil {
		t.Fatal(err)
	}
	return s, path, row, cfg, now, out, saved
}

func TestWAFBodyRetentionReviewedCurrentAndHistorySurviveRepeatedFreshServices(t *testing.T) {
	for _, history := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "history"}[history], func(t *testing.T) {
			s, path, row, cfg, now, out, saved := reviewedRetentionFixture(t, history)
			original, err := s.wafBodyRetentionInventory(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			selected := out.Operation
			if history {
				selected = &out.History[0]
			}
			want := append([]string{}, selected.Plan.Selected...)
			sort.Strings(want)
			for i := 2; i <= 4; i++ {
				fresh := New(s.Config)
				actual, err := fresh.wafRetainedUnknownArchiveIDs(context.Background(), out)
				if err != nil || !reflect.DeepEqual(actual, want) {
					t.Fatal(actual, want, err)
				}
				_, err = runRetentionFixture(t, fresh, cfg, now.Add(time.Duration(i)*time.Minute), func(string) error { t.Fatal("review authorized a later deletion"); return nil })
				if err == nil || !strings.Contains(err.Error(), "后续自动清理暂停") {
					t.Fatal(err)
				}
			}
			actual, _ := os.ReadFile(s.wafBodyRetentionPath())
			live, _ := os.ReadFile(path)
			remaining, err := s.wafBodyRetentionInventory(context.Background())
			if err != nil || !bytes.Equal(actual, saved) || !bytes.Equal(live, row) || !reflect.DeepEqual(original, remaining) {
				t.Fatal("preserved evidence changed", err)
			}
		})
	}
}

func TestWAFBodyRetentionReviewedResidualIndexCopyAndLinksBlockWithoutFollowing(t *testing.T) {
	for _, kind := range []string{"index-only", "copy-only", "symbolic-copy", "symbolic-index", "writable-directory", "symbolic-directory", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			s, path, row, cfg, now, out, saved := reviewedRetentionFixture(t, false)
			directory := s.wafBodyLogArchiveDirectory()
			id := out.Operation.Plan.Selected[0]
			index := filepath.Join(directory, id+".json")
			copy := filepath.Join(directory, id+".log")
			external := filepath.Join(t.TempDir(), "untouched-evidence")
			if err := os.WriteFile(external, []byte("owned outside evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "index-only":
				if err := os.Remove(copy); err != nil {
					t.Fatal(err)
				}
			case "copy-only":
				if err := os.Remove(index); err != nil {
					t.Fatal(err)
				}
			case "symbolic-copy", "symbolic-index":
				target := copy
				if kind == "symbolic-index" {
					target = index
				}
				if err := os.Rename(target, filepath.Join(t.TempDir(), "original-private-evidence")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, target); err != nil {
					t.Fatal(err)
				}
			case "writable-directory":
				if err := os.Chmod(directory, 0770); err != nil {
					t.Fatal(err)
				}
			case "symbolic-directory":
				target := filepath.Join(t.TempDir(), "original-private-archives")
				if err := os.Rename(directory, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, directory); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			if kind == "canceled" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			ids, err := s.wafRetainedUnknownArchiveIDs(ctx, out)
			if kind == "writable-directory" || kind == "symbolic-directory" || kind == "canceled" {
				if err == nil {
					t.Fatal("unsafe directory/context accepted", kind)
				}
			} else if err != nil || !reflect.DeepEqual(ids, func() []string { v := append([]string{}, out.Operation.Plan.Selected...); sort.Strings(v); return v }()) {
				t.Fatal(ids, err)
			}
			_, err = runRetentionFixture(t, New(s.Config), cfg, now.Add(2*time.Minute), func(string) error { t.Fatal("residual evidence caused deletion"); return nil })
			if err == nil {
				t.Fatal("residual plan was not blocked", kind)
			}
			actual, _ := os.ReadFile(s.wafBodyRetentionPath())
			live, _ := os.ReadFile(path)
			outside, _ := os.ReadFile(external)
			if !bytes.Equal(actual, saved) || !bytes.Equal(live, row) || string(outside) != "owned outside evidence" {
				t.Fatal("evidence changed", kind)
			}
		})
	}
}

func TestWAFBodyRetentionReviewedStatusAndManualDigestResolution(t *testing.T) {
	s, path, row, cfg, now, out, saved := reviewedRetentionFixture(t, false)
	base := "/v1/software/nginx-waf/body-log/retention"
	manifest, _ := json.Marshal(softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, InstalledAt: core.Now(), Settings: core.WAFSettings(cfg)})
	if err := os.WriteFile(s.softwareManifestPath("nginx-waf"), manifest, 0640); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Available, Enabled bool
		BlockedUnknown     bool     `json:"blocked_unknown"`
		BlockedRetained    bool     `json:"blocked_retained_unknown"`
		IDs                []string `json:"retained_unknown_archive_ids"`
	}
	status := func() {
		t.Helper()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", base, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	status()
	want := append([]string{}, out.Operation.Plan.Selected...)
	sort.Strings(want)
	if !result.Available || !result.Enabled || result.BlockedUnknown || !result.BlockedRetained || !reflect.DeepEqual(result.IDs, want) {
		t.Fatal(result)
	}
	_, sha, err := s.readWAFBodyRetentionRecord()
	if err != nil {
		t.Fatal(err)
	}
	review := httptest.NewRecorder()
	s.Handler().ServeHTTP(review, httptest.NewRequest("POST", base+"/retain", strings.NewReader(`{"sha256":"`+sha+`","acknowledge_unknown_deletion_not_repeated":true}`)))
	if review.Code != 409 {
		t.Fatal("reviewed plan accepted repeated authorization", review.Code)
	}
	actual, _ := os.ReadFile(s.wafBodyRetentionPath())
	if !bytes.Equal(actual, saved) {
		t.Fatal("status/repeated review changed evidence")
	}
	for _, id := range out.Operation.Plan.Selected {
		entry, _, err := s.readWAFBodyLogIndex(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.removeWAFBodyLogArchive(context.Background(), id, entry.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	status()
	if result.BlockedRetained || len(result.IDs) != 0 {
		t.Fatal("manual digest-bound resolution still blocked", result)
	}
	// New explicitly owned snapshots may subsequently expire; the original
	// uncertain plan remains uncertain in history and is never replayed.
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
	fresh, err := runRetentionFixture(t, New(s.Config), cfg, now.Add(2*time.Minute), nil)
	if err != nil || fresh.Operation.State != "completed" || len(fresh.Operation.Deleted) != 2 || len(fresh.History) != 1 || !reflect.DeepEqual(fresh.History[0], *out.Operation) {
		t.Fatal("new cleanup destroyed uncertain history", fresh, err)
	}
	for _, id := range fresh.Operation.Plan.Selected {
		for _, original := range out.Operation.Plan.Selected {
			if id == original {
				t.Fatal("original plan reselected")
			}
		}
	}
	live, _ := os.ReadFile(path)
	if !bytes.Equal(live, row) {
		t.Fatal("manual resolution changed current log")
	}
}
