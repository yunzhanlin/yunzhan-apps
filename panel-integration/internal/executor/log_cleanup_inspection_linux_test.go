//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestLogCleanupInspectionUnknownShowsActualIdentitiesWithoutChangingDBOrLogs(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "original")
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, func(context.Context) error {
		siteLogFixtureWrite(t, filepath.Join(logs, name), "new bytes")
		return errors.New("reopen result unknown")
	}); e == nil {
		t.Fatal("unknown operation accepted")
	}
	paths := []string{filepath.Join(s.Config.StateDir, "log-cleanup/operations.sqlite"), filepath.Join(logs, name), filepath.Join(logs, name+"."+now.Format("20060102-150405"))}
	before := map[string][32]byte{}
	for _, path := range paths {
		body, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		before[path] = sha256.Sum256(body)
	}
	out, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || !out.ReadOnly || out.State != "unknown" || out.RequestID != in.RequestID || len(out.PlanSHA256) != 64 || len(out.Files) != 1 || out.Files[0].State != "different_inode" || out.Files[0].ArchiveState != "original_inode_unchanged" {
		t.Fatal(out, e)
	}
	for _, path := range paths {
		body, e := os.ReadFile(path)
		if e != nil || sha256.Sum256(body) != before[path] {
			t.Fatal("inspection modified evidence", path, e)
		}
	}
	if _, e = s.inspectSiteLogCleanup(t.Context(), core.ID(), in.RequestID); e == nil {
		t.Fatal("cross-site record inspected")
	}
}

func TestLogCleanupInspectionMissingRecordDoesNotCreateStateOrInferSuccess(t *testing.T) {
	s, in, _, _ := siteLogLedgerFixture(t)
	out, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || !out.ReadOnly || out.State != "not_recorded" || out.Result != nil || out.Files == nil {
		t.Fatal(out, e)
	}
	if _, e = os.Lstat(filepath.Join(s.Config.StateDir, "log-cleanup")); !os.IsNotExist(e) {
		t.Fatal("read created ledger", e)
	}
}

func TestLogCleanupInspectionRefusesAmbiguousOrForeignPlanBeforeFileAccess(t *testing.T) {
	for _, plan := range []string{`{"Rotate":[],"Rotate":[],"Delete":[]}`, `{"Rotate":null,"Delete":[]}`, `{"Rotate":[{"name":"../../outside","inode":1,"bytes":0,"modified_at":"2026-10-08T11:00:00Z"}],"Delete":[]}`} {
		s, in, _, now := siteLogLedgerFixture(t)
		if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e != nil {
			t.Fatal(e)
		}
		db, closeDB, e := s.openSiteLogLedger(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.Exec(`UPDATE operations SET plan=? WHERE request_id=?`, plan, in.RequestID)
		closeDB()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID); e == nil {
			t.Fatal("untrusted plan adopted", plan)
		}
	}
}
