//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func siteLogLedgerFixture(t *testing.T) (*Service, core.LogCleanupRequest, string, time.Time) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	logs := filepath.Join(root, "var/log/nginx")
	for _, dir := range []string{state, logs} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	s := New(Config{StateDir: state, SystemRoot: root})
	in := core.LogCleanupRequest{RequestID: core.ID(), SiteID: core.ID(), RetentionDays: 2}
	now := time.Date(2026, 10, 8, 11, 0, 0, 0, time.UTC)
	return s, in, logs, now
}

func siteLogFixtureWrite(t *testing.T, path, body string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(body), 0640); e != nil {
		t.Fatal(e)
	}
}

func TestLogCleanupLedgerCompletedReplaySurvivesFreshServiceAndDifferentClock(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "before")
	siteLogFixtureWrite(t, filepath.Join(logs, name+".20260901-100000"), "retired")
	called := 0
	reopen := func(context.Context) error {
		called++
		siteLogFixtureWrite(t, filepath.Join(logs, name), "after")
		return nil
	}
	result, e := s.guardedSiteLogCleanup(t.Context(), in, now, reopen)
	if e != nil || result.Rotated != 1 || result.Deleted != 1 || called != 1 {
		t.Fatal(result, e, called)
	}
	in.Attempt = 1
	replay, e := New(s.Config).guardedSiteLogCleanup(t.Context(), in, now.Add(48*time.Hour), reopen)
	if e != nil || !reflect.DeepEqual(replay, result) || called != 1 {
		t.Fatal("replayed file mutations", replay, e, called)
	}
	if body, e := os.ReadFile(filepath.Join(logs, name)); e != nil || string(body) != "after" {
		t.Fatal("new bytes changed", e)
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer closeDB()
	var plan, state string
	if e = db.QueryRow(`SELECT state,plan FROM operations WHERE request_id=?`, in.RequestID).Scan(&state, &plan); e != nil || state != "completed" || !strings.Contains(plan, name) || strings.Contains(plan, "before") {
		t.Fatal("durable identity plan missing or leaked contents", e, state, plan)
	}
}

func TestLogCleanupLedgerUnknownCannotBeRetriedOrBypassed(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "before")
	siteLogFixtureWrite(t, filepath.Join(logs, name+".20260901-100000"), "retired")
	called := 0
	reopen := func(context.Context) error {
		called++
		siteLogFixtureWrite(t, filepath.Join(logs, name), "new bytes")
		return errors.New("unknown reopen")
	}
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, reopen); e == nil {
		t.Fatal("failure accepted")
	}
	for _, same := range []bool{true, false} {
		attempt := in
		if same {
			attempt.Attempt = 1
		} else {
			attempt.RequestID = core.ID()
		}
		if _, e := New(s.Config).guardedSiteLogCleanup(t.Context(), attempt, now.Add(time.Hour), reopen); e == nil {
			t.Fatal("unknown operation bypassed", same)
		}
	}
	if called != 1 {
		t.Fatal("unsafe repeat", called)
	}
	for suffix, want := range map[string]string{"": "new bytes", ".20261008-110000": "before", ".20260901-100000": "retired"} {
		if body, e := os.ReadFile(filepath.Join(logs, name+suffix)); e != nil || string(body) != want {
			t.Fatal("unknown evidence changed", suffix, e)
		}
	}
}

func TestLogCleanupLedgerRejectsMissingRetryAndDifferentBoundParameters(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	in.Attempt = 1
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e == nil {
		t.Fatal("missing original attempt repeated")
	}
	in.Attempt = 0
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*core.LogCleanupRequest){func(v *core.LogCleanupRequest) { v.SiteID = core.ID() }, func(v *core.LogCleanupRequest) { v.RetentionDays++ }} {
		copy := in
		change(&copy)
		if _, e := s.guardedSiteLogCleanup(t.Context(), copy, now, nil); e == nil {
			t.Fatal("request ID reused with different parameters")
		}
	}
	entries, e := os.ReadDir(logs)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid requests mutated empty logs", e)
	}
}

func TestLogCleanupLedgerCancelledAndInvalidPreflightHaveNoOperationRecord(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := s.guardedSiteLogCleanup(ctx, in, now, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Lstat(filepath.Join(s.Config.StateDir, "log-cleanup")); !os.IsNotExist(e) {
		t.Fatal("already cancelled request created state", e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	siteLogFixtureWrite(t, outside, "preserved")
	if e := os.Symlink(outside, filepath.Join(logs, "panel-"+in.SiteID+".access.log")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e == nil {
		t.Fatal("invalid preflight accepted")
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer closeDB()
	var count int
	if e = db.QueryRow(`SELECT count(*) FROM operations`).Scan(&count); e != nil || count != 0 {
		t.Fatal("preflight committed mutation intent", e, count)
	}
	if body, e := os.ReadFile(outside); e != nil || string(body) != "preserved" {
		t.Fatal("external bytes changed", e)
	}
}

func TestLogCleanupLedgerPrivateFileAndRecoveryLinksAreNeverAdopted(t *testing.T) {
	for _, kind := range []string{"lock-hardlink", "lock-symlink", "db-hardlink", "db-symlink", "journal-symlink", "writable-directory"} {
		t.Run(kind, func(t *testing.T) {
			s, in, logs, now := siteLogLedgerFixture(t)
			db, closeDB, e := s.openSiteLogLedger(t.Context())
			if e != nil || db == nil {
				t.Fatal(e)
			}
			closeDB()
			base := filepath.Join(s.Config.StateDir, "log-cleanup")
			outside := filepath.Join(t.TempDir(), "outside")
			if e = os.WriteFile(outside, []byte("external evidence"), 0600); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(base, "operation.lock")
			if strings.HasPrefix(kind, "db-") {
				path = filepath.Join(base, "operations.sqlite")
			}
			if kind == "journal-symlink" {
				path = filepath.Join(base, "operations.sqlite-journal")
			}
			if kind == "writable-directory" {
				if e = os.Chmod(base, 0770); e != nil {
					t.Fatal(e)
				}
			} else {
				if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
					t.Fatal(e)
				}
				if strings.HasSuffix(kind, "hardlink") {
					e = os.Link(outside, path)
				} else {
					e = os.Symlink(outside, path)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e = s.guardedSiteLogCleanup(t.Context(), in, now, nil); e == nil {
				t.Fatal("unsafe ledger adopted", kind)
			}
			if body, e := os.ReadFile(outside); e != nil || string(body) != "external evidence" {
				t.Fatal("external file changed", e)
			}
			entries, e := os.ReadDir(logs)
			if e != nil || len(entries) != 0 {
				t.Fatal("ledger rejection changed logs", e)
			}
		})
	}
}

func TestLogCleanupLedgerLockRespectsCancellationWithoutDuplicateMutation(t *testing.T) {
	s, in, _, now := siteLogLedgerFixture(t)
	_, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer closeDB()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, e = s.guardedSiteLogCleanup(ctx, in, now, nil); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("second execution did not honour lock deadline", e)
	}
}

func TestLogCleanupLedgerMalformedCompletedRecordIsNeverRepeated(t *testing.T) {
	s, in, _, now := siteLogLedgerFixture(t)
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e != nil {
		t.Fatal(e)
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`UPDATE operations SET result='{"rotated":0,"deleted":0,"deleted_bytes":0,"files":null}' WHERE request_id=?`, in.RequestID)
	closeDB()
	if e != nil {
		t.Fatal(e)
	}
	called := false
	if _, e = s.guardedSiteLogCleanup(t.Context(), in, now, func(context.Context) error { called = true; return nil }); e == nil || called {
		t.Fatal("corrupt completion repeated", e, called)
	}
}
