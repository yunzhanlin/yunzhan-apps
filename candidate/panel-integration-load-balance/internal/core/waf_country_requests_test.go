package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestWAFCountryRequestLedgerBindsActorCompletePayloadAndOriginalTerminal(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	ctx := context.Background()
	in := countryDataSelectionFixture()
	key := ID()
	id, replayed, err := s.queueWAFCountryData(ctx, in, key, u.ID)
	if err != nil || replayed || !ValidID(id) {
		t.Fatal(id, replayed, err)
	}
	read, err := readWAFCountryOriginal(ctx, s.DB, id)
	raw, _ := json.Marshal(in)
	if err != nil || read.Actor != u.ID || read.Job.Payload != string(raw) || read.PayloadSHA != Hash(string(raw)) || read.Key != key || !SameWAFCountryDataSelection(read.Selection, in) {
		t.Fatal(read, err)
	}
	again, replayed, err := s.queueWAFCountryData(ctx, in, key, u.ID)
	if err != nil || !replayed || again != id {
		t.Fatal("original queue forked", again, replayed, err)
	}
	other := accessUser(t, s, "other-country-admin", "admin", []string{"runtimes", "security"})
	if _, _, err := s.queueWAFCountryData(ctx, in, key, other.ID); err == nil {
		t.Fatal("other actor adopted original")
	}
	changed := in
	changed.Countries = []string{"US"}
	if _, _, err := s.queueWAFCountryData(ctx, changed, key, u.ID); err == nil {
		t.Fatal("original complete country selection replaced")
	}
	if _, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID); err == nil {
		t.Fatal("parallel replacement download queued")
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='original failure' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	again, replayed, err = s.queueWAFCountryData(ctx, in, key, u.ID)
	if err != nil || !replayed || again != id {
		t.Fatal("failed original replayed", again, replayed, err)
	}
	var count int
	var state, message string
	if s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&count) != nil || count != 1 || s.DB.QueryRow(`SELECT state,error FROM runtime_jobs WHERE id=?`, id).Scan(&state, &message) != nil || state != "failed" || message != "original failure" {
		t.Fatal("historical failure changed")
	}
}

func TestWAFCountryRequestUnboundOrCorruptOriginalCannotBeAdopted(t *testing.T) {
	for _, kind := range []string{"legacy", "actor", "hash", "created", "duplicate-audit", "wrong-key", "changed-payload"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			ctx := context.Background()
			in := countryDataSelectionFixture()
			key := ID()
			id, _, err := s.queueWAFCountryData(ctx, in, key, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "legacy":
				_, err = s.DB.Exec(`DELETE FROM waf_country_requests WHERE job_id=?`, id)
			case "actor":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET actor_id=? WHERE job_id=?`, ID(), id)
			case "hash":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET payload_sha256=? WHERE job_id=?`, strings.Repeat("d", 64), id)
			case "created":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET created_at='2026-10-20T00:00:00.000Z' WHERE job_id=?`, id)
			case "duplicate-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.queue',?,'queued',?)`, u.ID, id, Now())
			case "wrong-key":
				_, err = s.DB.Exec(`UPDATE waf_country_requests SET idempotency_key=? WHERE job_id=?`, ID(), id)
			case "changed-payload":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET payload=payload||' ' WHERE id=?`, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.queueWAFCountryData(ctx, in, key, u.ID); err == nil {
				t.Fatal("corrupt or unbound original adopted")
			}
			if _, err := readWAFCountryOriginal(ctx, s.DB, id); err == nil && kind != "actor" {
				t.Fatal("corrupt binding read as complete")
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&count) != nil || count != 1 {
				t.Fatal("replacement queue created")
			}
		})
	}
}

func TestWAFCountryRequestBindingFailureRollsBackJobAndAudit(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_country_binding BEFORE INSERT ON waf_country_requests BEGIN SELECT RAISE(ABORT,'fixture binding refusal');END`); err != nil {
		t.Fatal(err)
	}
	if id, _, err := s.queueWAFCountryData(context.Background(), countryDataSelectionFixture(), ID(), u.ID); err == nil || id != "" {
		t.Fatal("partial binding committed", id, err)
	}
	for _, table := range []string{"runtime_jobs", "waf_country_requests", "audit_logs WHERE action='waf.country.queue'"} {
		var count int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal(table, count, err)
		}
	}
}

func TestWAFCountryDispatchIntentNeverAuthorizesAnotherPostOrDeletedActor(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	ctx := context.Background()
	in := countryDataSelectionFixture()
	id, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := readWAFCountryOriginal(ctx, s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafCountryDispatchBoundary(ctx, original.Job, true); err == nil {
		t.Fatal("unclaimed queued job dispatched")
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='running' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	original, err = readWAFCountryOriginal(ctx, s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{false, true} {
		already, err := s.wafCountryDispatchBoundary(ctx, original.Job, commit)
		if err != nil || already {
			t.Fatal(already, err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	already, err := s.wafCountryDispatchBoundary(ctx, original.Job, true)
	if err != nil || !already {
		t.Fatal("late revocation prevented read-only original reconciliation", already, err)
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, id).Scan(&count) != nil || count != 1 {
		t.Fatal("more than one submit intent")
	}
	if _, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID); err == nil {
		t.Fatal("revoked user queued new download")
	}
	if _, err := s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.dispatch',?,?,?)`, u.ID, id, Hash(original.Job.Payload), Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafCountryDispatchBoundary(ctx, original.Job, true); err == nil {
		t.Fatal("duplicate dispatch authority accepted")
	}
}

func TestWAFCountryRequestAndDispatchRecheckCurrentMenusBeforeDurableIntent(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	ctx := context.Background()
	id, _, err := s.queueWAFCountryData(ctx, countryDataSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='running' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	original, err := readWAFCountryOriginal(ctx, s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafCountryDispatchBoundary(ctx, original.Job, true); err == nil {
		t.Fatal("revoked actor reached submit boundary")
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch'`).Scan(&count) != nil || count != 0 {
		t.Fatal("unauthorized intent committed")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.queueWAFCountryData(cancelled, countryDataSelectionFixture(), ID(), u.ID); err == nil {
		t.Fatal("cancelled queue accepted")
	}
}

func TestWAFCountryOriginalDirectoryIsActorScopedCompleteAndReadOnly(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	other := accessUser(t, s, "country-directory-other", "admin", []string{"runtimes", "security"})
	ctx := context.Background()
	id, _, err := s.queueWAFCountryData(ctx, countryDataSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.readWAFCountryRequests(ctx, u.ID, "")
	if err != nil || !page.ReadOnly || page.ActorID != u.ID || len(page.Entries) != 1 || page.Entries[0].ID != id {
		t.Fatal(page, err)
	}
	detail, err := s.readWAFCountryRequest(ctx, u.ID, id)
	if err != nil || !detail.ReadOnly || detail.ActorID != u.ID || detail.Request != page.Entries[0] || !SameWAFCountryDataSelection(detail.Selection, countryDataSelectionFixture()) {
		t.Fatal(detail, err)
	}
	foreign, err := s.readWAFCountryRequests(ctx, other.ID, "")
	if err != nil || len(foreign.Entries) != 0 {
		t.Fatal("other actor directory leaked", foreign, err)
	}
	if _, err := s.readWAFCountryRequest(ctx, other.ID, id); err == nil {
		t.Fatal("other actor read complete original")
	}
	if _, err := s.readWAFCountryRequests(ctx, u.ID, "../"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action LIKE 'waf.country.%'`).Scan(&count) != nil || count != 1 {
		t.Fatal("read created mutation intent")
	}
	if _, err := s.DB.Exec(`UPDATE waf_country_requests SET payload_sha256=? WHERE job_id=?`, strings.Repeat("a", 64), id); err != nil {
		t.Fatal(err)
	}
	if got, err := s.readWAFCountryRequests(ctx, u.ID, ""); err == nil || len(got.Entries) != 0 {
		t.Fatal("partial corrupt directory returned", got, err)
	}
}

func TestWAFCountryActorEnvelopeCannotSubmitAnotherOrStaleAccountsDraft(t *testing.T) {
	actor := ID()
	raw, _ := json.Marshal(map[string]any{"actor_id": actor, "selection": countryDataSelectionFixture()})
	got, err := decodeWAFCountryActorBody(raw, actor)
	if err != nil || !SameWAFCountryDataSelection(got, countryDataSelectionFixture()) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{string(raw) + `{}`, strings.Replace(string(raw), actor, ID(), 1), strings.TrimSuffix(string(raw), "}") + `,"actor_id":"` + actor + `"}`, strings.Replace(string(raw), `"actor_id"`, `"Actor_id"`, 1), strings.Replace(string(raw), `"action":"download"`, `"action":"activate"`, 1), strings.TrimSuffix(string(raw), "}") + `,"source":"https://evil.invalid"}`, `{"actor_id":"` + actor + `","selection":null}`} {
		if _, err := decodeWAFCountryActorBody([]byte(bad), actor); err == nil {
			t.Fatal("foreign or malformed draft accepted", bad)
		}
	}
}

func TestWAFCountryAccessRoleMenusAndUserExistenceAreRecheckedBeforeIntent(t *testing.T) {
	for _, kind := range []string{"role", "menus", "deleted"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "country-revoked-original", "admin", nil)
			ctx := context.Background()
			in := countryDataSelectionFixture()
			id, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='running' WHERE id=?`, id); err != nil {
				t.Fatal(err)
			}
			original, err := readWAFCountryOriginal(ctx, s.DB, id)
			if err != nil {
				t.Fatal(err)
			}
			statement := `UPDATE app_user_roles SET role='viewer' WHERE user_id=?`
			if kind == "menus" {
				statement = `INSERT INTO app_user_menus VALUES(?,'["runtimes"]',1)`
			}
			if kind == "deleted" {
				statement = `DELETE FROM users WHERE id=?`
			}
			if _, err := s.DB.Exec(statement, u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.wafCountryDispatchBoundary(ctx, original.Job, true); err == nil {
				t.Fatal("revoked original dispatched", kind)
			}
			if _, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID); err == nil {
				t.Fatal("revoked user created queue", kind)
			}
			if _, err := s.readWAFCountryRequest(ctx, u.ID, id); err == nil {
				t.Fatal("revoked user read private original", kind)
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch'`).Scan(&count) != nil || count != 0 {
				t.Fatal("unauthorized intent persisted", kind, count)
			}
		})
	}
}

func TestWAFCountryNativeCoreProofIsReadOnlyAndRequiresOriginalIntentCurrentActorAndExactReceipt(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	ctx := context.Background()
	in := countryDataSelectionFixture()
	id, _, err := s.queueWAFCountryData(ctx, in, ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='running' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	original, err := readWAFCountryOriginal(ctx, s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('nginx-waf','nginx-waf',?,?,'nginx-waf',?)`, in.AppVersion, in.AppManifestSHA, Now()); err != nil {
		t.Fatal(err)
	}
	if s.ValidateWAFCountryDataNative(ctx, id, u.ID, original.PayloadSHA) == nil {
		t.Fatal("receipt alone authorized Root without dispatch intent")
	}
	if already, err := s.wafCountryDispatchBoundary(ctx, original.Job, true); err != nil || already {
		t.Fatal(already, err)
	}
	if err := s.ValidateWAFCountryDataNative(ctx, id, u.ID, original.PayloadSHA); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{ID(), original.PayloadSHA}, {u.ID, Hash("foreign payload")}} {
		if s.ValidateWAFCountryDataNative(ctx, id, pair[0], pair[1]) == nil {
			t.Fatal("foreign Root context accepted")
		}
	}
	if _, err := s.DB.Exec(`UPDATE app_registry_receipts SET sha256=? WHERE app_id='nginx-waf'`, Hash("other app receipt")); err != nil {
		t.Fatal(err)
	}
	if s.ValidateWAFCountryDataNative(ctx, id, u.ID, original.PayloadSHA) == nil {
		t.Fatal("changed app receipt accepted")
	}
	if _, err := s.DB.Exec(`UPDATE app_registry_receipts SET sha256=? WHERE app_id='nginx-waf'`, in.AppManifestSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if s.ValidateWAFCountryDataNative(ctx, id, u.ID, original.PayloadSHA) == nil {
		t.Fatal("late revocation granted new Root write authority")
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action LIKE 'waf.country.%'`).Scan(&count) != nil || count != 2 {
		t.Fatal("Root proof query wrote or duplicated evidence", count)
	}
}
