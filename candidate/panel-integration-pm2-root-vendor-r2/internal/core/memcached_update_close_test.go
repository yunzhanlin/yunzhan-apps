package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemcachedCloseUnsubmittedAtomicFenceRetainsVersionAndOfflineReplay(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	d := seed.Dispatch
	before, receipt := memcachedStoreCounts(t, s), memcachedStoreReceipt(t, s, d.ProjectID)
	closed, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input)
	if err != nil || closed.ActorID != actor.ID || closed.Input != d.Input || closureStatus(closed).State != "closed_without_submission" {
		t.Fatal("genuine unsubmitted closure", closed, err)
	}
	for range 3 {
		prior, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input)
		if err != nil || prior != closed || memcachedStoreCounts(t, s) != before || memcachedStoreReceipt(t, s, d.ProjectID) != receipt {
			t.Fatal("closure replay changed a queue/version/original identity", err)
		}
	}
	if _, _, err := s.reserveMemcachedUpdate(t.Context(), actor.ID, seed); err == nil {
		t.Fatal("a late original producer bypassed the durable closure")
	}
	if _, found, err := s.memcachedClosureForActor(t.Context(), actor.ID, d.ProjectID, d.RequestID); err != nil || !found {
		t.Fatal("read-only closure observation", found, err)
	}
	var audits int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app.memcached.close'`).Scan(&audits) != nil || audits != 1 {
		t.Fatal("closure must retain one audit", audits)
	}
	token := Token()
	if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), actor.ID, "close-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	a := &Server{Store: s} // No catalog/executor: reads/replays must stay offline.
	mux := http.NewServeMux()
	a.memcachedUpdateProducerRoutes(mux)
	a.memcachedUpdateStatusRoutes(mux)
	for _, action := range []string{"GET", "POST", "close"} {
		method, route := action, "/api/app-registry/memcached/instances/"+d.ProjectID+"/updates"
		if action == "GET" {
			route += "/" + d.RequestID
		}
		if action == "close" {
			method = "POST"
			route += "/" + d.RequestID + "/close"
		}
		body, _ := json.Marshal(d.Input)
		r := httptest.NewRequest(method, route, bytes.NewReader(body))
		r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
		r.Header.Set("X-CSRF-Token", "close-csrf")
		r.Header.Set("Idempotency-Key", d.RequestID)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var status memcachedUpdateStatus
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || !status.StateKnown || status.State != "closed_without_submission" || status.JobID != "" || memcachedStoreCounts(t, s) != before {
			t.Fatal("closed status/replay dispatched or fabricated a job", action, w.Code, w.Body.String())
		}
	}
}

func TestMemcachedCloseNeverReleasesAnExistingReservationOrOriginalNativeGrant(t *testing.T) {
	for _, phase := range []string{"reserved", "unknown", "committed", "rolled_back", "failed_safe"} {
		t.Run(phase, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			switch phase {
			case "unknown":
				if err := s.markMemcachedUpdateUnknown(t.Context(), actor.ID, seed.Dispatch.RequestID); err != nil {
					t.Fatal(err)
				}
			case "committed":
				if _, err := s.reconcileMemcachedUpdate(t.Context(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")); err != nil {
					t.Fatal(err)
				}
			case "rolled_back":
				if _, err := s.reconcileMemcachedUpdate(t.Context(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "rollback_started", "rolled_back")); err != nil {
					t.Fatal(err)
				}
			case "failed_safe":
				if _, err := s.reconcileMemcachedUpdate(t.Context(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "failed_safe")); err != nil {
					t.Fatal(err)
				}
			}
			before := memcachedStoreCounts(t, s)
			d := seed.Dispatch
			if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err == nil || memcachedStoreCounts(t, s) != before {
				t.Fatal("an actual original reservation was closed", phase, err)
			}
		})
	}
}

func TestMemcachedCloseRequiresOriginalActorProjectInputAndCurrentFullAuthority(t *testing.T) {
	for _, scenario := range []string{"other-actor", "other-project", "changed-input", "revoked", "scoped", "missing-ack"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			d := seed.Dispatch
			if scenario != "missing-ack" {
				if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "other-actor":
				actor = accessUser(t, s, "foreign-close-admin", "admin", nil)
			case "other-project":
				d.ProjectID = ID()
			case "changed-input":
				d.Input.ExpectedProjectSHA256 = strings.Repeat("f", 64)
			case "revoked":
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); err != nil {
					t.Fatal(err)
				}
			case "scoped":
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+ID()+`"]`, actor.ID); err != nil {
					t.Fatal(err)
				}
			case "missing-ack":
				d.Input.AcknowledgeCacheLoss = false
			}
			before := memcachedStoreCounts(t, s)
			if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err == nil || memcachedStoreCounts(t, s) != before {
				t.Fatal("closure changed identity or revoked authority", scenario)
			}
		})
	}
}

func TestMemcachedCloseCorruptEvidenceNeverBecomesPermissionForALateReservation(t *testing.T) {
	for _, sql := range []string{
		`DELETE FROM memcached_update_closures`,
		`DELETE FROM audit_logs WHERE action='app.memcached.close'`,
		`UPDATE memcached_update_closures SET closure_sha256='` + strings.Repeat("a", 64) + `'`,
		`UPDATE audit_logs SET actor='` + strings.Repeat("a", 32) + `' WHERE action='app.memcached.close'`,
		`UPDATE memcached_update_closures SET input_record='{}'`,
		`CREATE TRIGGER foreign_memcached_close AFTER INSERT ON memcached_update_closures BEGIN SELECT 1; END`,
		`DROP TABLE memcached_update_closures`,
	} {
		t.Run(sql, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			d := seed.Dispatch
			if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(sql); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.reserveMemcachedUpdate(t.Context(), actor.ID, seed); err == nil {
				t.Fatal("corruption allowed a late reservation")
			}
			if _, _, err := s.memcachedClosureForActor(t.Context(), actor.ID, d.ProjectID, d.RequestID); err == nil {
				t.Fatal("corruption became a reliable closed/missing status")
			}
		})
	}
}

func TestMemcachedCloseAndReservationRaceHasOnlyOneDurableOutcome(t *testing.T) {
	for range 8 {
		s, actor, seed := memcachedStoreFixture(t)
		d := seed.Dispatch
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var closed, reserved bool
		go func() {
			defer wg.Done()
			<-start
			_, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input)
			closed = err == nil
		}()
		go func() {
			defer wg.Done()
			<-start
			_, fresh, err := s.reserveMemcachedUpdate(t.Context(), actor.ID, seed)
			reserved = err == nil && fresh
		}()
		close(start)
		wg.Wait()
		if closed == reserved {
			t.Fatal("expected exactly one original outcome", closed, reserved)
		}
		var rows, closures int
		if s.DB.QueryRow(`SELECT (SELECT count(*) FROM memcached_update_requests),(SELECT count(*) FROM memcached_update_closures)`).Scan(&rows, &closures) != nil || rows+closures != 1 {
			t.Fatal(rows, closures)
		}
		if closed {
			if _, _, err := s.reserveMemcachedUpdate(t.Context(), actor.ID, seed); err == nil {
				t.Fatal("late reserved behind close")
			}
		} else {
			if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err == nil {
				t.Fatal("closed original reservation")
			}
		}
	}
}

func TestMemcachedCloseConcurrentRepeatsRetainOneAuditAndOriginalCanonicalRecord(t *testing.T) {
	s, actor, seed := memcachedStoreFixture(t)
	d := seed.Dispatch
	results := make(chan memcachedUpdateClosure, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			closed, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input)
			if err == nil {
				results <- closed
			}
		}()
	}
	wg.Wait()
	close(results)
	var first *memcachedUpdateClosure
	for result := range results {
		if first == nil {
			v := result
			first = &v
		}
		if !reflect.DeepEqual(*first, result) {
			t.Fatal("repeat closure changed identity")
		}
	}
	if first == nil {
		t.Fatal("no original closure committed")
	}
	var audits int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app.memcached.close'`).Scan(&audits) != nil || audits != 1 {
		t.Fatal(audits)
	}
}

func TestMemcachedCloseHTTPRefusesMissingCSRFRevocationAliasesAndUnknownBodiesWithoutAJob(t *testing.T) {
	for _, scenario := range []string{"no-session", "csrf", "revoked", "scoped", "wrong-app", "bad-key", "query", "duplicate", "extra", "no-ack", "oversize", "reserved"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			d := seed.Dispatch
			if scenario == "reserved" {
				memcachedStoreReserve(t, s, actor, seed)
			}
			token := Token()
			if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), actor.ID, "close-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			if scenario == "revoked" {
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "scoped" {
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+ID()+`"]`, actor.ID); err != nil {
					t.Fatal(err)
				}
			}
			app, key := "memcached", d.RequestID
			want := 400
			switch scenario {
			case "no-session":
				want = 401
			case "csrf", "revoked", "scoped":
				want = 403
			case "wrong-app":
				app = "redis"
				want = 404
			case "bad-key":
				key = "unknown"
				want = 404
			case "query":
				want = 404
			case "reserved":
				want = 409
			}
			input := d.Input
			if scenario == "no-ack" {
				input.AcknowledgeCacheLoss = false
			}
			body, _ := json.Marshal(input)
			if scenario == "duplicate" {
				body = append([]byte(`{"expected_version":"other",`), body[1:]...)
			}
			if scenario == "extra" {
				body = append([]byte(`{"cancel_native_job":true,`), body[1:]...)
			}
			if scenario == "oversize" {
				body = bytes.Repeat([]byte(" "), MaxMemcachedUpdateInputBytes+1)
			}
			route := "/api/app-registry/" + app + "/instances/" + d.ProjectID + "/updates/" + key + "/close"
			if scenario == "query" {
				route += "?cancel=true"
			}
			a := &Server{Store: s}
			mux := http.NewServeMux()
			a.memcachedUpdateProducerRoutes(mux)
			r := httptest.NewRequest("POST", route, bytes.NewReader(body))
			if scenario != "no-session" {
				r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			}
			if scenario != "csrf" {
				r.Header.Set("X-CSRF-Token", "close-csrf")
			}
			before := memcachedStoreCounts(t, s)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			var closures int
			if w.Code != want || memcachedStoreCounts(t, s) != before || s.DB.QueryRow(`SELECT count(*) FROM memcached_update_closures`).Scan(&closures) != nil || closures != 0 {
				t.Fatal("refused close changed job/version/closure", scenario, w.Code, w.Body.String(), closures)
			}
		})
	}
}

func TestMemcachedCloseMigrationDoesNotRepairAnOrphanOrChangedSchema(t *testing.T) {
	for _, scenario := range []string{"legitimate-old-database", "orphan-audit", "foreign-trigger", "changed-table"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			d := seed.Dispatch
			if scenario == "orphan-audit" {
				if _, err := s.closeMemcachedUpdate(t.Context(), actor.ID, d.ProjectID, d.RequestID, d.Input); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "legitimate-old-database", "orphan-audit":
				if _, err := s.DB.Exec(`DROP TABLE memcached_update_closures`); err != nil {
					t.Fatal(err)
				}
			case "foreign-trigger":
				if _, err := s.DB.Exec(`CREATE TRIGGER foreign_close AFTER INSERT ON memcached_update_closures BEGIN SELECT 1; END`); err != nil {
					t.Fatal(err)
				}
			case "changed-table":
				if _, err := s.DB.Exec(`ALTER TABLE memcached_update_closures ADD COLUMN foreign_authority TEXT`); err != nil {
					t.Fatal(err)
				}
			}
			err := s.migrateMemcachedUpdates()
			if scenario == "legitimate-old-database" {
				if err != nil {
					t.Fatal("genuine previous format migration", err)
				}
				return
			}
			if err == nil {
				t.Fatal("partial/orphan/changed closure schema repaired")
			}
			if scenario == "orphan-audit" {
				var n int
				if s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='memcached_update_closures'`).Scan(&n) != nil || n != 0 {
					t.Fatal("missing table silently restored")
				}
			}
		})
	}
}
