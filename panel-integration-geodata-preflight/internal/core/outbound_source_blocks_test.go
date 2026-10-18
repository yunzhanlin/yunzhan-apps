package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func sourceBlockFixture(t *testing.T) (*Server, identity, NotificationChannel, outboundSourceBlock) {
	t.Helper()
	s, a := outboundFixture(t)
	actor := accessUser(t, s, "source-owner", "admin", nil)
	c := outboundCreate(t, s, "http://127.0.0.1:12345")
	if _, e := s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-11','{"sites":-1}',?)`, Now()); e != nil {
		t.Fatal(e)
	}
	outboundEvent(t, s, "monitor")
	if e := s.QueueDailyNotification("2026-10-11"); e != nil {
		t.Fatal(e)
	}
	outboundEvent(t, s, "sync")
	if e := s.QueueOutboundNotifications(); !errors.Is(e, errOutboundSourceBlocked) {
		t.Fatal("source not quarantined", e)
	}
	b, e := readOutboundSourceBlock(s.DB.QueryRow("SELECT "+outboundSourceBlockFields+` FROM notification_source_blocks WHERE channel_id=?`, c.ID))
	if e != nil {
		t.Fatal(e)
	}
	return a, actor, c, b
}
func TestOutboundSourceIsolationFaultsCannotAdvanceWithoutRetainedEvidence(t *testing.T) {
	for _, fault := range []string{"source-insert", "source-audit", "cursor-update"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := outboundFixture(t)
			c := outboundCreate(t, s, "http://127.0.0.1:12345")
			other, e := s.SaveNotificationChannel("", NotificationChannelInput{Name: "other", URL: "http://127.0.0.1:12346", Secret: strings.Repeat("s", 32), Enabled: true, Kinds: []string{"monitor", "sync"}})
			if e != nil {
				t.Fatal(e)
			}
			statement := map[string]string{"source-insert": fmt.Sprintf("CREATE TRIGGER own_source_fault BEFORE INSERT ON notification_source_blocks WHEN NEW.channel_id='%s' BEGIN SELECT RAISE(ABORT,'owned source fault'); END", c.ID), "source-audit": "CREATE TRIGGER own_source_fault BEFORE INSERT ON audit_logs WHEN NEW.action='notification.source.block' BEGIN SELECT RAISE(ABORT,'owned source fault'); END", "cursor-update": fmt.Sprintf("CREATE TRIGGER own_source_fault BEFORE UPDATE ON notification_channels WHEN NEW.id='%s' BEGIN SELECT RAISE(ABORT,'owned source fault'); END", c.ID)}[fault]
			if _, e = s.DB.Exec(statement); e != nil {
				t.Fatal(e)
			}
			outboundEvent(t, s, "monitor")
			if e = s.QueueDailyNotification("2026-10-11"); e != nil {
				t.Fatal(e)
			}
			outboundEvent(t, s, "sync")
			if e = s.QueueOutboundNotifications(); e == nil {
				t.Fatal("source persistence/audit failure hidden")
			}
			var cursor, blocks, deliveries, otherDeliveries int
			if e = s.DB.QueryRow(`SELECT watermark,(SELECT count(*) FROM notification_source_blocks WHERE channel_id=?),(SELECT count(*) FROM notification_deliveries WHERE channel_id=?),(SELECT count(*) FROM notification_deliveries WHERE channel_id=?) FROM notification_channels WHERE id=?`, c.ID, c.ID, other.ID, c.ID).Scan(&cursor, &blocks, &deliveries, &otherDeliveries); e != nil {
				t.Fatal(e)
			}
			if cursor != 0 || blocks != 0 || deliveries != 0 || otherDeliveries != 2 {
				t.Fatal("non-atomic source fault or unrelated channel starvation", cursor, blocks, deliveries, otherDeliveries)
			}
		})
	}
}
func TestOutboundSourceReconcileOriginalIdentityAndAuditCommitTogether(t *testing.T) {
	for _, fault := range []string{"none", "state", "delivery", "audit"} {
		t.Run(fault, func(t *testing.T) {
			a, actor, c, b := sourceBlockFixture(t)
			s := a.Store
			if _, e := s.DB.Exec(`UPDATE app_daily_reports SET report='{"sites":3,"running_sites":0}' WHERE day='2026-10-11'`); e != nil {
				t.Fatal(e)
			}
			triggers := map[string]string{"state": "CREATE TRIGGER own_resolve_fault BEFORE UPDATE ON notification_source_blocks BEGIN SELECT RAISE(ABORT,'owned reconcile fault'); END", "delivery": fmt.Sprintf("CREATE TRIGGER own_resolve_fault BEFORE INSERT ON notification_deliveries WHEN NEW.event_id='%s' BEGIN SELECT RAISE(ABORT,'owned reconcile fault'); END", b.EventID), "audit": "CREATE TRIGGER own_resolve_fault BEFORE INSERT ON audit_logs WHEN NEW.action='notification.source.reconcile' BEGIN SELECT RAISE(ABORT,'owned reconcile fault'); END"}
			if fault != "none" {
				if _, e := s.DB.Exec(triggers[fault]); e != nil {
					t.Fatal(e)
				}
			}
			out, e := a.reconcileOutboundSource(context.Background(), actor, c.ID, b.ID, b.sha(), c.Revision)
			var state string
			var count, audits int
			if err := s.DB.QueryRow(`SELECT state,(SELECT count(*) FROM notification_deliveries WHERE event_id=?),(SELECT count(*) FROM audit_logs WHERE action='notification.source.reconcile') FROM notification_source_blocks WHERE id=?`, b.EventID, b.ID).Scan(&state, &count, &audits); err != nil {
				t.Fatal(err)
			}
			if fault != "none" {
				if e == nil || state != "blocked" || count != 0 || audits != 0 {
					t.Fatal("partial reconcile escaped rollback", out, e, state, count, audits)
				}
				return
			}
			if e != nil || out["id"] != b.ID || out["event_id"] != b.EventID || out["already_resolved"] != false || state != "resolved" || count != 1 || audits != 1 {
				t.Fatal("exact original reconcile missing", out, e, state, count, audits)
			}
			again, e := a.reconcileOutboundSource(context.Background(), actor, c.ID, b.ID, b.sha(), c.Revision)
			if e != nil || again["already_resolved"] != true || again["delivery_id"] != out["delivery_id"] {
				t.Fatal("idempotent original replay changed delivery", again, e)
			}
			var total int
			if e = s.DB.QueryRow(`SELECT count(*) FROM notification_deliveries`).Scan(&total); e != nil || total != 3 {
				t.Fatal("reconcile duplicated delivery", total, e)
			}
			if e = s.QueueOutboundNotifications(); e != nil {
				t.Fatal("resolved source still blocks unrelated queue", e)
			}
		})
	}
}
func TestOutboundSourceReconcileRequiresCurrentActorVersionAndValidOriginal(t *testing.T) {
	a, actor, c, b := sourceBlockFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		ctx              context.Context
		actor            identity
		channel, id, sha string
		revision         int64
	}{
		{ctx, actor, c.ID, b.ID, b.sha(), c.Revision},
		{context.Background(), actor, c.ID, b.ID, strings.Repeat("f", 64), c.Revision},
		{context.Background(), actor, ID(), b.ID, b.sha(), c.Revision},
		{context.Background(), actor, c.ID, b.ID, b.sha(), c.Revision + 1},
		{context.Background(), identity{ID: ID(), Username: "foreign"}, c.ID, b.ID, b.sha(), c.Revision},
		{context.Background(), actor, c.ID, b.ID, b.sha(), c.Revision},
	} {
		if _, e := a.reconcileOutboundSource(input.ctx, input.actor, input.channel, input.id, input.sha, input.revision); e == nil {
			t.Fatal("unclear original/authority accepted")
		}
	}
	if _, e := a.Store.DB.Exec(`UPDATE app_daily_reports SET report='{"sites":0}' WHERE day='2026-10-11'`); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Store.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := a.reconcileOutboundSource(context.Background(), actor, c.ID, b.ID, b.sha(), c.Revision); e == nil {
		t.Fatal("stale administrator authority accepted")
	}
	current, e := readOutboundSourceBlock(a.Store.DB.QueryRow("SELECT "+outboundSourceBlockFields+" FROM notification_source_blocks WHERE id=?", b.ID))
	if e != nil || current.State != "blocked" || current.sha() != b.sha() {
		t.Fatal("refused input modified original block", current, e)
	}
}
func TestOutboundSourceBadStorageIsNotClassifiedAsQuarantinableContent(t *testing.T) {
	a, _, c, _ := sourceBlockFixture(t)
	if _, e := a.Store.DB.Exec("DROP TABLE app_daily_reports"); e != nil {
		t.Fatal(e)
	}
	_, _, e := readDailyReportRecord(context.Background(), a.Store.DB, "2026-10-11")
	if e == nil || errors.Is(e, errDailyReportInvalid) || errors.Is(e, sql.ErrNoRows) {
		t.Fatal("database failure called corrupt source", e)
	}
	if e = a.Store.QueueDailyNotification("2026-10-12"); e != nil {
		t.Fatal(e)
	}
	var before int
	if e = a.Store.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, c.ID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e = a.Store.QueueOutboundNotifications(); e == nil {
		t.Fatal("storage failure ignored")
	}
	var after int
	if e = a.Store.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, c.ID).Scan(&after); e != nil || after != before {
		t.Fatal("database failure advanced cursor", before, after, e)
	}
}

func TestOutboundSourceInventoryPreservesMalformedRowsAndBoundedPages(t *testing.T) {
	for _, column := range []string{"source_id", "severity", "id", "state"} {
		t.Run(column, func(t *testing.T) {
			a, _, c, b := sourceBlockFixture(t)
			value := strings.Repeat("owned-private", 10000)
			if column == "state" {
				value = "blocked"
				if _, e := a.Store.DB.Exec("UPDATE notification_source_blocks SET resolved_at=123 WHERE id=?", b.ID); e != nil {
					t.Fatal(e)
				}
			} else if _, e := a.Store.DB.Exec("UPDATE notification_source_blocks SET "+column+"=? WHERE id=?", value, b.ID); e != nil {
				t.Fatal(e)
			}
			rows, total, e := a.Store.OutboundSourceBlocks(context.Background(), c.ID)
			if e == nil || rows != nil || total != 0 {
				t.Fatal("malformed source page returned early rows or empty healthy inventory", rows, total, e)
			}
			var count int
			if e = a.Store.DB.QueryRow("SELECT count(*) FROM notification_source_blocks").Scan(&count); e != nil || count != 1 {
				t.Fatal("readonly inventory repaired or deleted corrupt row", count, e)
			}
		})
	}
	a, _, c, b := sourceBlockFixture(t)
	for i := 0; i < 100; i++ {
		if _, e := a.Store.DB.Exec(`INSERT INTO notification_source_blocks(id,channel_id,channel_revision,event_id,sequence,kind,severity,event_created_at,source_id,state,created_at) VALUES(?,?,?,?,?,'daily','info',?,'2026-10-11','blocked',?)`, ID(), c.ID, c.Revision, ID(), i+10, b.EventCreatedAt, b.CreatedAt); e != nil {
			t.Fatal(e)
		}
	}
	rows, total, e := a.Store.OutboundSourceBlocks(context.Background(), c.ID)
	if e != nil || len(rows) != 100 || total != 101 {
		t.Fatal("bounded source page falsely complete", len(rows), total, e)
	}
}
func TestOutboundSourceOriginalBlockSurvivesSourceRetentionAndSQLiteReopen(t *testing.T) {
	a, _, c, b := sourceBlockFixture(t)
	s := a.Store
	if _, e := s.DB.Exec("DELETE FROM notifications WHERE id=?", b.EventID); e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, file string
	if e := s.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); e != nil {
		t.Fatal(e)
	}
	key := s.encryptionKey
	if e := s.DB.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(file)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	reopened.encryptionKey = key
	rows, total, e := reopened.OutboundSourceBlocks(context.Background(), c.ID)
	if e != nil || total != 1 || len(rows) != 1 || rows[0]["id"] != b.ID || rows[0]["source_sha"] != b.sha() {
		t.Fatal("source retention/reopen lost original block", rows, total, e)
	}
	var ordinary int
	if e = reopened.DB.QueryRow("SELECT count(*) FROM notification_deliveries WHERE channel_id=?", c.ID).Scan(&ordinary); e != nil || ordinary != 2 {
		t.Fatal("reopen changed surrounding normal queue", ordinary, e)
	}
}
