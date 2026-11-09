//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func siteLogUnknownContinuationFixture(t *testing.T) (*Service, core.LogCleanupContinueRequest, string) {
	t.Helper()
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "original")
	siteLogFixtureWrite(t, filepath.Join(logs, name+".20260901-100000"), "retired")
	_, e := s.guardedSiteLogCleanup(t.Context(), in, now, func(context.Context) error {
		siteLogFixtureWrite(t, filepath.Join(logs, name), "new-active")
		return errors.New("controlled unknown")
	})
	if e == nil {
		t.Fatal("unknown fixture unexpectedly succeeded")
	}
	inspection, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || inspection.State != "unknown" || inspection.Result != nil {
		t.Fatal(inspection, e)
	}
	return s, core.LogCleanupContinueRequest{RequestID: in.RequestID, SiteID: in.SiteID, PlanSHA256: inspection.PlanSHA256, AcknowledgeUnknown: true}, logs
}

func TestLogCleanupContinuationPreservesUnknownResultAndAllFilesAndAllowsNewIDOnly(t *testing.T) {
	s, in, logs := siteLogUnknownContinuationFixture(t)
	before := map[string]string{}
	entries, e := os.ReadDir(logs)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		body, e := os.ReadFile(filepath.Join(logs, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		before[entry.Name()] = string(body)
	}
	calls := 0
	verify := func(context.Context, []plannedSiteLog, []plannedSiteLog) error { calls++; return nil }
	out, e := s.continueSiteLogCleanup(t.Context(), in, verify)
	if e != nil || calls != 1 || out.PlanSHA256 != in.PlanSHA256 || !siteLogSHA256(out.EvidenceSHA256) {
		t.Fatal(out, e, calls)
	}
	replay, e := New(s.Config).continueSiteLogCleanup(t.Context(), in, verify)
	if e != nil || calls != 1 || replay != out {
		t.Fatal("replayed native verification", replay, e, calls)
	}
	checked, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || checked.State != "unknown" || checked.Result != nil || checked.Continuation == nil || *checked.Continuation != out {
		t.Fatal("unknown credited as success", checked, e)
	}
	for name, body := range before {
		actual, e := os.ReadFile(filepath.Join(logs, name))
		if e != nil || string(actual) != body {
			t.Fatal("continuation changed file", name, e)
		}
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	pending, e := siteLogPendingOperations(t.Context(), db, in.SiteID)
	closeDB()
	if e != nil || pending != 0 {
		t.Fatal("verified new operation remained blocked", pending, e)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	_, e = s.guardedSiteLogCleanup(t.Context(), core.LogCleanupRequest{RequestID: in.RequestID, SiteID: in.SiteID, RetentionDays: 2, Attempt: 1}, now, nil)
	if e == nil {
		t.Fatal("same unknown ID was replayed after continuation")
	}
	result, e := s.guardedSiteLogCleanup(t.Context(), core.LogCleanupRequest{RequestID: core.ID(), SiteID: in.SiteID, RetentionDays: 2}, now, func(context.Context) error {
		siteLogFixtureWrite(t, filepath.Join(logs, "panel-"+in.SiteID+".access.log"), "next-active")
		return nil
	})
	if e != nil || result.Rotated != 1 || result.Deleted != 1 {
		t.Fatal("new operation not executed independently", result, e)
	}
}

func TestLogCleanupContinuationRejectsForeignDigestChangedArchivesAndUnverifiableNativeState(t *testing.T) {
	for _, fault := range []string{"site", "digest", "acknowledgment", "archive_missing", "expired_replaced", "native", "during_verification"} {
		t.Run(fault, func(t *testing.T) {
			s, in, logs := siteLogUnknownContinuationFixture(t)
			name := "panel-" + in.SiteID + ".access.log"
			verify := func(context.Context, []plannedSiteLog, []plannedSiteLog) error { return nil }
			switch fault {
			case "site":
				in.SiteID = core.ID()
			case "digest":
				in.PlanSHA256 = core.Hash("foreign-plan")
			case "acknowledgment":
				in.AcknowledgeUnknown = false
			case "archive_missing":
				if e := os.Rename(filepath.Join(logs, name+".20261008-110000"), filepath.Join(logs, "retained-outside-plan")); e != nil {
					t.Fatal(e)
				}
			case "expired_replaced":
				if e := os.Rename(filepath.Join(logs, name+".20260901-100000"), filepath.Join(logs, "retained-expired")); e != nil {
					t.Fatal(e)
				}
				siteLogFixtureWrite(t, filepath.Join(logs, name+".20260901-100000"), "replacement")
			case "native":
				verify = func(context.Context, []plannedSiteLog, []plannedSiteLog) error {
					return errors.New("cannot verify native identity")
				}
			case "during_verification":
				verify = func(context.Context, []plannedSiteLog, []plannedSiteLog) error {
					siteLogFixtureWrite(t, filepath.Join(logs, name+".20260901-100000"), "changed-during-inspection")
					return nil
				}
			}
			if _, e := s.continueSiteLogCleanup(t.Context(), in, verify); e == nil {
				t.Fatal("unsafe continuation accepted")
			}
			db, closeDB, e := s.openSiteLogLedger(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer closeDB()
			var count int
			if e = db.QueryRowContext(t.Context(), "SELECT count(*) FROM operation_continuations").Scan(&count); e != nil || count != 0 {
				t.Fatal("refused continuation persisted success", count, e)
			}
		})
	}
}

func TestLogCleanupContinuationCorruptedEvidenceNeverUnblocksOrReturnsAcceptedReplay(t *testing.T) {
	s, in, _ := siteLogUnknownContinuationFixture(t)
	if _, e := s.continueSiteLogCleanup(t.Context(), in, func(context.Context, []plannedSiteLog, []plannedSiteLog) error { return nil }); e != nil {
		t.Fatal(e)
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(t.Context(), `UPDATE operation_continuations SET evidence='{}' WHERE request_id=?`, in.RequestID); e != nil {
		closeDB()
		t.Fatal(e)
	}
	if _, e = siteLogPendingOperations(t.Context(), db, in.SiteID); e == nil {
		closeDB()
		t.Fatal("corrupted continuation unblocked site")
	}
	closeDB()
	called := false
	if _, e = s.continueSiteLogCleanup(t.Context(), in, func(context.Context, []plannedSiteLog, []plannedSiteLog) error { called = true; return nil }); e == nil || called {
		t.Fatal("corrupted evidence replay accepted", e, called)
	}
	if _, e = s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID); e == nil {
		t.Fatal("corrupted continuation exposed as verified")
	}
}
