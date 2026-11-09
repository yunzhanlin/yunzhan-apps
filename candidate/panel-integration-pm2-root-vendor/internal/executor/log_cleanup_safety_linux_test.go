//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogCleanupPreflightNeverPartiallyRotatesInvalidSecondLogOrArchive(t *testing.T) {
	for _, kind := range []string{"second-symlink", "second-hardlink", "expired-symlink", "archive-collision", "group-writable"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			id := core.ID()
			now := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
			active := "panel-" + id + ".access.log"
			bad := "panel-" + id + ".error.log"
			write := func(name, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0640); err != nil {
					t.Fatal(err)
				}
			}
			write(active, "original-access")
			write("outside-evidence", "outside")
			if kind == "expired-symlink" {
				bad = active + ".20260901-120000"
			}
			switch kind {
			case "second-symlink", "expired-symlink":
				if err := os.Symlink(filepath.Join(base, "outside-evidence"), filepath.Join(base, bad)); err != nil {
					t.Fatal(err)
				}
			case "second-hardlink":
				if err := os.Link(filepath.Join(base, "outside-evidence"), filepath.Join(base, bad)); err != nil {
					t.Fatal(err)
				}
			case "archive-collision":
				write(active+".20261008-100000", "older-evidence")
			case "group-writable":
				write(bad, "error-evidence")
				if err := os.Chmod(filepath.Join(base, bad), 0660); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			_, err := cleanupSiteLogsAt(t.Context(), base, id, 2, now, func(context.Context) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("invalid preflight mutated logs", err, called)
			}
			body, e := os.ReadFile(filepath.Join(base, active))
			if e != nil || string(body) != "original-access" {
				t.Fatal("original access changed", string(body), e)
			}
			outside, e := os.ReadFile(filepath.Join(base, "outside-evidence"))
			if e != nil || string(outside) != "outside" {
				t.Fatal("outside changed", e)
			}
			if kind == "archive-collision" {
				body, e = os.ReadFile(filepath.Join(base, active+".20261008-100000"))
				if e != nil || string(body) != "older-evidence" {
					t.Fatal("archive overwritten", e)
				}
			} else if _, e = os.Lstat(filepath.Join(base, active+".20261008-100000")); !os.IsNotExist(e) {
				t.Fatal("partial first rotation", e)
			}
		})
	}
}

func TestLogCleanupReopenFailureKeepsNewActiveBytesAndOriginalArchive(t *testing.T) {
	base := t.TempDir()
	id := core.ID()
	now := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	for _, kind := range []string{"access", "error"} {
		if err := os.WriteFile(filepath.Join(base, "panel-"+id+"."+kind+".log"), []byte("old-"+kind), 0640); err != nil {
			t.Fatal(err)
		}
	}
	expired := "panel-" + id + ".access.log.20260901-100000"
	os.WriteFile(filepath.Join(base, expired), []byte("retired"), 0640)
	_, err := cleanupSiteLogsAt(t.Context(), base, id, 2, now, func(context.Context) error {
		for _, kind := range []string{"access", "error"} {
			if e := os.WriteFile(filepath.Join(base, "panel-"+id+"."+kind+".log"), []byte("new-"+kind), 0640); e != nil {
				return e
			}
		}
		return errors.New("partial real reopen result unknown")
	})
	if err == nil || !strings.Contains(err.Error(), "需人工核对") {
		t.Fatal("unsafe recovery accepted", err)
	}
	for _, kind := range []string{"access", "error"} {
		name := "panel-" + id + "." + kind + ".log"
		for suffix, want := range map[string]string{"": "new-" + kind, ".20261008-100000": "old-" + kind} {
			b, e := os.ReadFile(filepath.Join(base, name+suffix))
			if e != nil || string(b) != want {
				t.Fatal("recovery clobbered bytes", name+suffix, string(b), e)
			}
		}
	}
	if b, e := os.ReadFile(filepath.Join(base, expired)); e != nil || string(b) != "retired" {
		t.Fatal("expired evidence removed after unknown reopen", e)
	}
}

func TestLogCleanupEmptyAndAlreadyCancelledAreNonMutating(t *testing.T) {
	base := t.TempDir()
	id := core.ID()
	now := time.Now().UTC()
	r, e := cleanupSiteLogsAt(t.Context(), base, id, 2, now, nil)
	if e != nil || r.Rotated != 0 || r.Deleted != 0 {
		t.Fatal("empty directory was not harmless", r, e)
	}
	name := "panel-" + id + ".access.log"
	os.WriteFile(filepath.Join(base, name), []byte("preserved"), 0640)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	_, e = cleanupSiteLogsAt(ctx, base, id, 2, now, func(context.Context) error { called = true; return nil })
	if !errors.Is(e, context.Canceled) || called {
		t.Fatal("cancelled operation ran", e, called)
	}
	if b, e := os.ReadFile(filepath.Join(base, name)); e != nil || string(b) != "preserved" {
		t.Fatal("cancelled data changed", e)
	}
}

func TestLogCleanupRejectsSymlinkOrWritableDirectoryAndExpiredBacklog(t *testing.T) {
	base := t.TempDir()
	id := core.ID()
	now := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	link := filepath.Join(t.TempDir(), "linked-logs")
	if e := os.Symlink(base, link); e != nil {
		t.Fatal(e)
	}
	if _, e := cleanupSiteLogsAt(t.Context(), link, id, 2, now, nil); e == nil {
		t.Fatal("symlink directory accepted")
	}
	os.Chmod(base, 0770)
	if _, e := cleanupSiteLogsAt(t.Context(), base, id, 2, now, nil); e == nil {
		t.Fatal("writable directory accepted")
	}
	os.Chmod(base, 0700)
	for i := 0; i <= siteLogExpiredLimit; i++ {
		at := now.Add(-time.Duration(i+72) * time.Hour)
		name := "panel-" + id + ".access.log." + at.Format("20060102-150405")
		if e := os.WriteFile(filepath.Join(base, name), []byte(fmt.Sprint(i)), 0640); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := cleanupSiteLogsAt(t.Context(), base, id, 2, now, nil); e == nil {
		t.Fatal("unbounded expired deletion accepted")
	}
	entries, e := os.ReadDir(base)
	if e != nil || len(entries) != siteLogExpiredLimit+1 {
		t.Fatal("backlog was partially deleted", len(entries), e)
	}
}

func TestLogCleanupDoesNotRemoveArchiveWrittenAfterPreflight(t *testing.T) {
	base := t.TempDir()
	id := core.ID()
	now := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	active := "panel-" + id + ".access.log"
	old := active + ".20260901-100000"
	os.WriteFile(filepath.Join(base, active), []byte("active"), 0640)
	os.WriteFile(filepath.Join(base, old), []byte("old"), 0640)
	_, e := cleanupSiteLogsAt(t.Context(), base, id, 2, now, func(context.Context) error {
		return os.WriteFile(filepath.Join(base, old), []byte("newly-appended-archive"), 0640)
	})
	if e == nil {
		t.Fatal("changed retired inode deleted")
	}
	if b, e := os.ReadFile(filepath.Join(base, old)); e != nil || string(b) != "newly-appended-archive" {
		t.Fatal("newly written evidence lost", e)
	}
}
