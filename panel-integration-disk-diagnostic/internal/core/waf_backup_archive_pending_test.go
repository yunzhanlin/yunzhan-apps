package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func wafArchivePendingIdentity(t *testing.T, s *Store, name string) identity {
	t.Helper()
	u := identity{Username: name}
	if err := s.DB.QueryRow(`SELECT id FROM users WHERE username=?`, name).Scan(&u.ID); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestWAFBackupArchiveRecoverySurvivesActualStoreReopenAndIsActorBoundReadOnly(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, _ := wafBackupArchiveCoreFixture()
	raw, _ := json.Marshal(in)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		pending, err := readWAFBackupArchivePending(r.Context(), s.DB, u.ID)
		if err != nil || pending == nil || pending.ID != in.ID || pending.SHA != in.SHA {
			t.Fatal("handoff preceded committed original ticket/audit", pending, err)
		}
		return nil, errors.New("explicit Core transport fixture: reply lost; not a native move")
	})}}
	if w := wafBackupArchiveCorePost(a, "/api/software/nginx-waf/archive-config-backup", string(raw), cookie, csrf, a.Config.Origin); w.Code != 503 || calls != 1 {
		t.Fatal(w.Code, w.Body.String(), calls)
	}
	var sequence int
	var databaseName, databasePath string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&sequence, &databaseName, &databasePath); err != nil || databaseName != "main" || databasePath == "" {
		t.Fatal("actual private SQLite file", err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	s.DB = reopened.DB // Keep the fixture's cleanup and Server on this actual reopened store.
	path := "/api/software/nginx-waf/config-backup-archive-request"
	w := wafTaskTestRead(a, path, cookie)
	var recovery WAFBackupArchiveRecovery
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &recovery) != nil || !recovery.ReadOnly || recovery.Pending == nil || recovery.Pending.ID != in.ID || recovery.Pending.SHA != in.SHA || recovery.Pending.CreatedAt == "" || calls != 1 {
		t.Fatal("reopened original pending read", w.Code, w.Body.String(), calls)
	}
	for _, private := range []string{"actor_id", "username", "confirm", "request_audit_id", "configuration", "/private"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("recovery exposed private fields", private)
		}
	}
	accessUser(t, s, "second-waf-admin", "admin", []string{"runtimes", "security"})
	second := login("second-waf-admin")
	w = wafTaskTestRead(a, path, second)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &recovery) != nil || recovery.Pending != nil || !recovery.ReadOnly {
		t.Fatal("other actor inherited original ticket", w.Code, w.Body.String())
	}
	for _, forbidden := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(forbidden)); w.Code != 403 {
			t.Fatal("recovery expanded authority", forbidden, w.Code)
		}
	}
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, query := range []string{"?", "?actor_id=" + u.ID, "?resource_id=" + in.ID} {
		if w := wafTaskTestRead(a, path+query, second); w.Code != 400 {
			t.Fatal("caller selected recovery owner", w.Code)
		}
	}
	if calls != 1 {
		t.Fatal("read-only recovery reached executor", calls)
	}
	t.Log("Actual SQLite close/reopen and authenticated actor-bound read; not process crash, cold boot, power loss or native executor acceptance")
}

func TestWAFBackupArchivePendingAndRequestedAuditCommitBeforeHandoffTogether(t *testing.T) {
	for _, kind := range []string{"request-audit", "ticket-insert"} {
		t.Run(kind, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			statement := `CREATE TRIGGER reject_owned_ticket BEFORE INSERT ON waf_config_backup_archive_pending BEGIN SELECT RAISE(ABORT,'owned ticket fixture'); END`
			if kind == "request-audit" {
				statement = `CREATE TRIGGER reject_owned_ticket BEFORE INSERT ON audit_logs WHEN NEW.action='waf.config-backup.archive-requested' BEGIN SELECT RAISE(ABORT,'owned requested-audit fixture'); END`
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			in, _ := wafBackupArchiveCoreFixture()
			raw, _ := json.Marshal(in)
			w := wafBackupArchiveCorePost(a, "/api/software/nginx-waf/archive-config-backup", string(raw), cookie, csrf, a.Config.Origin)
			if w.Code != 500 || !strings.Contains(w.Body.String(), "未发送") {
				t.Fatal(w.Code, w.Body.String())
			}
			for _, table := range []string{"waf_config_backup_archive_pending", "audit_logs WHERE action='waf.config-backup.archive-requested'"} {
				var count int
				if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
					t.Fatal("partial before-handoff transaction", table, count, err)
				}
			}
		})
	}
}

func TestWAFBackupArchiveConfirmedAuditAndOriginalTicketClosureAreAtomic(t *testing.T) {
	for _, kind := range []string{"confirmed-audit", "ticket-delete"} {
		t.Run(kind, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			in, out := wafBackupArchiveCoreFixture()
			raw, _ := json.Marshal(in)
			response, _ := json.Marshal(out)
			statement := `CREATE TRIGGER reject_owned_closure BEFORE DELETE ON waf_config_backup_archive_pending BEGIN SELECT RAISE(ABORT,'owned pending closure fixture'); END`
			if kind == "confirmed-audit" {
				statement = `CREATE TRIGGER reject_owned_closure BEFORE INSERT ON audit_logs WHEN NEW.action='waf.config-backup.archive-confirmed' BEGIN SELECT RAISE(ABORT,'owned confirmed-audit fixture'); END`
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(response))), Request: r}, nil
			})}}
			path := "/api/software/nginx-waf/archive-config-backup"
			if w := wafBackupArchiveCorePost(a, path, string(raw), cookie, csrf, a.Config.Origin); w.Code != 503 || calls != 1 {
				t.Fatal(w.Code, calls)
			}
			pending, err := readWAFBackupArchivePending(context.Background(), s.DB, u.ID)
			if err != nil || pending == nil || pending.ID != in.ID || pending.SHA != in.SHA {
				t.Fatal("failed closure lost original ticket", pending, err)
			}
			var count int
			if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-confirmed'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("partial result audit", count, err)
			}
			if _, err := s.DB.Exec(`DROP TRIGGER reject_owned_closure`); err != nil {
				t.Fatal(err)
			}
			if w := wafBackupArchiveCorePost(a, path, string(raw), cookie, csrf, a.Config.Origin); w.Code != 200 || calls != 2 {
				t.Fatal("explicit original retry", w.Code, w.Body.String(), calls)
			}
			if pending, err := readWAFBackupArchivePending(context.Background(), s.DB, u.ID); err != nil || pending != nil {
				t.Fatal("confirmed exact ticket remains", pending, err)
			}
		})
	}
}

func TestWAFBackupArchivePendingRejectsSupersedingAndCorruptRequestsWithoutRepair(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, _ := wafBackupArchiveCoreFixture()
	ctx := context.Background()
	if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
		t.Fatal(err)
	}
	original, _ := readWAFBackupArchivePending(ctx, s.DB, u.ID)
	for _, field := range []string{"id", "sha"} {
		other := in
		if field == "id" {
			other.ID = ID()
			other.Confirm = "ARCHIVE NGINX CONFIG " + other.ID
		} else {
			other.SHA = strings.Repeat("b", 64)
		}
		if err := s.beginWAFBackupArchive(ctx, u, other); !errors.Is(err, errWAFBackupArchivePendingConflict) {
			t.Fatal("different original identity superseded", err)
		}
	}
	if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
		t.Fatal("same-identity explicit retry refused", err)
	}
	again, err := readWAFBackupArchivePending(ctx, s.DB, u.ID)
	if err != nil || *again != *original {
		t.Fatal("original ticket replaced", again, err)
	}
	if _, err := s.DB.Exec(`UPDATE audit_logs SET target=? WHERE id=(SELECT request_audit_id FROM waf_config_backup_archive_pending WHERE actor_id=?)`, ID(), u.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err := readWAFBackupArchivePending(ctx, s.DB, u.ID); err == nil || pending != nil {
		t.Fatal("corrupt audit became an empty/valid ticket", pending, err)
	}
	if err := s.beginWAFBackupArchive(ctx, u, in); err == nil {
		t.Fatal("corrupt ticket was repaired or replaced")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_config_backup_archive_pending WHERE actor_id=?`, u.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("corrupt evidence deleted", count, err)
	}
}

func TestWAFBackupArchiveLateConfirmedReplayCannotCloseNewIdentity(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, out := wafBackupArchiveCoreFixture()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.finishWAFBackupArchive(ctx, u, in, out); err != nil {
		t.Fatal(err)
	}
	newer := in
	newer.ID = ID()
	newer.Confirm = "ARCHIVE NGINX CONFIG " + newer.ID
	if err := s.beginWAFBackupArchive(ctx, u, newer); err != nil {
		t.Fatal(err)
	}
	out.Replayed = true
	if err := s.finishWAFBackupArchive(ctx, u, in, out); err != nil {
		t.Fatal("already-started original replay completion", err)
	}
	if pending, err := readWAFBackupArchivePending(ctx, s.DB, u.ID); err != nil || pending == nil || pending.ID != newer.ID || pending.SHA != newer.SHA {
		t.Fatal("late completion closed another identity", pending, err)
	}
}

func TestWAFBackupArchiveCancelledOrRevokedBeginDoesNotRetainPartialRequest(t *testing.T) {
	for _, kind := range []string{"cancelled", "role-revoked", "menu-revoked"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			in, _ := wafBackupArchiveCoreFixture()
			ctx := context.Background()
			if kind == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if kind == "role-revoked" {
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, u.ID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "menu-revoked" {
				if _, err := s.DB.Exec(`UPDATE app_user_menus SET menu_ids='["runtimes"]' WHERE user_id=?`, u.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.beginWAFBackupArchive(ctx, u, in); err == nil {
				t.Fatal("cancelled/revoked handoff accepted")
			}
			for _, table := range []string{"waf_config_backup_archive_pending", "audit_logs WHERE action='waf.config-backup.archive-requested'"} {
				var count int
				if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
					t.Fatal("partial cancelled/revoked request", count, err)
				}
			}
		})
	}
}

func TestWAFBackupArchiveLogicalPendingBoundDoesNotDeleteEvidenceOrBlockSameIdentity(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, _ := wafBackupArchiveCoreFixture()
	ctx := context.Background()
	if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
		t.Fatal(err)
	}
	var auditID int64
	if err := s.DB.QueryRow(`SELECT request_audit_id FROM waf_config_backup_archive_pending WHERE actor_id=?`, u.ID).Scan(&auditID); err != nil {
		t.Fatal(err)
	}
	// Synthetic orphan identities fill only this private DB's logical bound;
	// they are not proof of real accounts, physical disk quota or fleet scale.
	if _, err := s.DB.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1023) INSERT INTO waf_config_backup_archive_pending SELECT printf('%032x',x),?,?,?,? FROM n`, in.ID, in.SHA, Now(), auditID); err != nil {
		t.Fatal(err)
	}
	other := accessUser(t, s, "bound-other-admin", "admin", []string{"runtimes", "security"})
	if err := s.beginWAFBackupArchive(ctx, other, in); err == nil {
		t.Fatal("logical pending bound bypassed")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_config_backup_archive_pending`).Scan(&count); err != nil || count != 1024 {
		t.Fatal("bound silently removed evidence", count, err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-requested'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("refused new request retained audit", count, err)
	}
	if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
		t.Fatal("bound refused original identity recovery", err)
	}
}

func TestWAFBackupArchiveUnavailableRecoveryFailsClosedWithoutExecutor(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	if _, err := s.DB.Exec(`ALTER TABLE waf_config_backup_archive_pending RENAME TO owned_unavailable_pending`); err != nil {
		t.Fatal(err)
	}
	w := wafTaskTestRead(a, "/api/software/nginx-waf/config-backup-archive-request", cookie)
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), `"pending":null`) || strings.Contains(w.Body.String(), "owned_unavailable") {
		t.Fatal("unavailable became absence or exposed SQL", w.Code, w.Body.String())
	}
}

func TestWAFBackupArchiveAccountRemovalRetainsEvidenceAndNewAccountCannotInheritIt(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, _ := wafBackupArchiveCoreFixture()
	ctx := context.Background()
	if err := s.beginWAFBackupArchive(ctx, u, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_logs WHERE id=(SELECT request_audit_id FROM waf_config_backup_archive_pending WHERE actor_id=?)`, u.ID); err == nil {
		t.Fatal("unresolved original request audit erased")
	}
	if _, err := s.DB.Exec(`DELETE FROM users WHERE id=?`, u.ID); err != nil {
		t.Fatal("pending blocked normal account removal", err)
	}
	newUser := accessUser(t, s, u.Username, "admin", []string{"runtimes", "security"})
	if newUser.ID == u.ID {
		t.Fatal("fixture reused actor ID")
	}
	if pending, err := readWAFBackupArchivePending(ctx, s.DB, newUser.ID); err != nil || pending != nil {
		t.Fatal("new same-name account inherited identity", pending, err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_config_backup_archive_pending WHERE actor_id=?`, u.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("account removal deleted unknown original evidence", count, err)
	}
	if err := s.beginWAFBackupArchive(ctx, u, in); err == nil {
		t.Fatal("removed account handed off original request")
	}
}
