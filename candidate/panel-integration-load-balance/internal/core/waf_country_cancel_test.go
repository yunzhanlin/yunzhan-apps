package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestWAFCountryCancelBeforeDispatchPreservesIdentityAndLateResults(t *testing.T) {
	for _, state := range []string{"queued", "running"} {
		t.Run(state, func(t *testing.T) {
			s, j, original, out := countryWorkerFixture(t)
			ctx := context.Background()
			if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, state, j.ID); err != nil {
				t.Fatal(err)
			}
			before, err := s.readWAFCountryRequest(ctx, original.Actor, j.ID)
			if err != nil || !before.CanCancelBeforeDispatch || before.Cancellation != nil {
				t.Fatal(before, err)
			}
			proof, err := s.cancelWAFCountryBeforeDispatch(ctx, original.Actor, j.ID, original.PayloadSHA, original.Selection)
			if err != nil || !proof.BeforeDispatch || proof.JobID != j.ID || proof.ActorID != original.Actor || proof.PayloadSHA != original.PayloadSHA || proof.AutomaticReplayAllowed {
				t.Fatal(proof, err)
			}
			for range 3 {
				repeated, err := s.cancelWAFCountryBeforeDispatch(ctx, original.Actor, j.ID, original.PayloadSHA, original.Selection)
				if err != nil || repeated != proof {
					t.Fatal("same cancellation changed original proof", repeated, err)
				}
			}
			lookup, err := s.readWAFCountryRequestKey(ctx, original.Actor, original.Key)
			if err != nil || lookup.Request == nil || lookup.Request.Cancellation == nil || *lookup.Request.Cancellation != proof || lookup.Request.CanCancelBeforeDispatch || lookup.Request.Result != nil || lookup.Request.Error != wafCountryCancelledMessage {
				t.Fatal("original request cannot prove cancellation", lookup, err)
			}
			if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err == nil || s.ValidateWAFCountryDataNative(ctx, j.ID, original.Actor, original.PayloadSHA) == nil {
				t.Fatal("cancelled original acquired Root dispatch authority")
			}
			if err := s.finishRuntime(j, "late failed/uncertain observation", nil, true); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(out)
			if err := s.finishWAFCountryResult(ctx, j, raw, original.Actor, original.Selection, nil); err != nil {
				t.Fatal(err)
			}
			// Even a worker already holding the old running snapshot can no
			// longer send its one POST. The transport must remain unused.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("cancelled original reached Root transport", r.Method, r.URL)
				w.WriteHeader(500)
			}))
			defer server.Close()
			runWAFCountryOriginal(ctx, ctx, s, countryWorkerClient(server), j, original, appcatalog.GeoDataEnvelope{})
			if countryWorkerState(t, s, j.ID) != "cancelled" || s.CheckWAFCountryUpgrade(ctx) != nil {
				t.Fatal("late observer changed cancellation or complete proof blocked upgrade")
			}
			page, err := s.readWAFCountryRequests(ctx, original.Actor, "")
			if err != nil || len(page.Entries) != 1 || page.Entries[0].State != "cancelled" {
				t.Fatal(page, err)
			}
			var results, audits int
			if s.DB.QueryRow(`SELECT count(*) FROM waf_country_results`).Scan(&results) != nil || results != 0 || s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action LIKE 'waf.country.%' AND target=?`, j.ID).Scan(&audits) != nil || audits != 2 {
				t.Fatal("cancellation produced Root results or duplicate audits")
			}
			id, replayed, err := s.queueWAFCountryData(ctx, original.Selection, original.Key, original.Actor)
			if err != nil || !replayed || id != j.ID || countryWorkerState(t, s, id) != "cancelled" {
				t.Fatal("old cancelled key created replacement work", id, replayed, err)
			}
			if id, replayed, err := s.queueWAFCountryData(ctx, original.Selection, ID(), original.Actor); err != nil || replayed || id == j.ID {
				t.Fatal("explicit distinct new request could not be queued", id, replayed, err)
			}
		})
	}
}

func TestWAFCountryCancellationRejectsIssuedForeignChangedRevokedAndTerminal(t *testing.T) {
	for _, mutation := range []string{"dispatch", "unknown-audit", "result", "foreign-actor", "changed-payload", "changed-selection", "revoked", "failed", "succeeded", "needs_attention", "dirty-steps", "error", "malformed-cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			s, j, o, out := countryWorkerFixture(t)
			actor, digest, selection := o.Actor, o.PayloadSHA, o.Selection
			var err error
			switch mutation {
			case "dispatch":
				_, err = s.wafCountryDispatchBoundary(context.Background(), j, true)
			case "unknown-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.unrecognized',?,'unknown',?)`, actor, j.ID, Now())
			case "result":
				raw, _ := json.Marshal(out)
				err = s.finishWAFCountryResult(context.Background(), j, raw, actor, selection, nil)
			case "foreign-actor":
				actor = accessUser(t, s, "foreign-country-admin", "admin", []string{"runtimes", "security"}).ID
			case "changed-payload":
				digest = strings.Repeat("1", 64)
			case "changed-selection":
				selection.Countries = []string{"US"}
			case "revoked":
				_, err = s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor)
			case "failed", "succeeded", "needs_attention", "malformed-cancelled":
				state := mutation
				if state == "malformed-cancelled" {
					state = "cancelled"
				}
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state=?,error='original fixed terminal' WHERE id=?`, state, j.ID)
			case "dirty-steps":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET steps='[{}]' WHERE id=?`, j.ID)
			case "error":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET error='original uncertain evidence' WHERE id=?`, j.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := countryWorkerState(t, s, j.ID)
			if _, err := s.cancelWAFCountryBeforeDispatch(context.Background(), actor, j.ID, digest, selection); err == nil || countryWorkerState(t, s, j.ID) != before {
				t.Fatal("non-cancellable original was adopted or rewritten", mutation, err)
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-before-dispatch'`).Scan(&count) != nil || count != 0 {
				t.Fatal("refused cancellation retained partial intent")
			}
		})
	}
}

func TestWAFCountryCancellationProofCorruptionNeverBecomesDrainedOrReadable(t *testing.T) {
	for _, query := range []string{
		`DELETE FROM audit_logs WHERE action='waf.country.cancel-before-dispatch'`,
		`INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='waf.country.cancel-before-dispatch'`,
		`UPDATE audit_logs SET actor='` + strings.Repeat("1", 32) + `' WHERE action='waf.country.cancel-before-dispatch'`,
		`UPDATE audit_logs SET result='` + strings.Repeat("2", 64) + `' WHERE action='waf.country.cancel-before-dispatch'`,
		`UPDATE audit_logs SET created_at='2000-01-01T00:00:00Z' WHERE action='waf.country.cancel-before-dispatch'`,
		`UPDATE audit_logs SET created_at='2000-01-01T00:00:00Z' WHERE action='waf.country.queue'`,
		`UPDATE runtime_jobs SET steps='null'`,
		`UPDATE runtime_jobs SET error='cancelled without proof'`,
		`UPDATE runtime_jobs SET updated_at='2000-01-01T00:00:00Z'`,
		`INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,'waf.country.dispatch',target,result,created_at FROM audit_logs WHERE action='waf.country.cancel-before-dispatch'`,
		`INSERT INTO waf_country_results(job_id,request_sha256,result_sha256,body,state,created_at) SELECT id,'` + strings.Repeat("a", 64) + `','` + strings.Repeat("b", 64) + `',x'7b7d','failed',created_at FROM runtime_jobs`,
	} {
		t.Run(query[:min(45, len(query))], func(t *testing.T) {
			s, j, o, _ := countryWorkerFixture(t)
			if _, err := s.cancelWAFCountryBeforeDispatch(context.Background(), o.Actor, j.ID, o.PayloadSHA, o.Selection); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := s.readWAFCountryRequest(context.Background(), o.Actor, j.ID); err == nil || s.CheckWAFCountryUpgrade(context.Background()) == nil {
				t.Fatal("corrupted cancellation treated as complete original")
			}
			if _, err := s.cancelWAFCountryBeforeDispatch(context.Background(), o.Actor, j.ID, o.PayloadSHA, o.Selection); err == nil {
				t.Fatal("corrupted cancellation repaired by another POST")
			}
		})
	}
}

func TestWAFCountryCancellationAndDispatchHaveOneDurableWinner(t *testing.T) {
	for range 16 {
		s, j, o, _ := countryWorkerFixture(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _ = s.cancelWAFCountryBeforeDispatch(context.Background(), o.Actor, j.ID, o.PayloadSHA, o.Selection)
		}()
		go func() { defer wg.Done(); <-start; _, _ = s.wafCountryDispatchBoundary(context.Background(), j, true) }()
		close(start)
		wg.Wait()
		var dispatches, cancellations int
		if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, j.ID).Scan(&dispatches) != nil || s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-before-dispatch' AND target=?`, j.ID).Scan(&cancellations) != nil || dispatches+cancellations != 1 {
			t.Fatal("race did not retain exactly one original boundary", dispatches, cancellations)
		}
		if cancellations == 1 {
			if countryWorkerState(t, s, j.ID) != "cancelled" || s.CheckWAFCountryUpgrade(context.Background()) != nil || s.ValidateWAFCountryDataNative(context.Background(), j.ID, o.Actor, o.PayloadSHA) == nil {
				t.Fatal("cancel winner retained executable authority")
			}
		} else if countryWorkerState(t, s, j.ID) != "running" {
			t.Fatal("cancel loser changed issued original state")
		}
	}
}

func TestWAFCountryCancelHTTPUsesCurrentOwnerCSRFAndOriginalBodyWithoutRoot(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, key := countryDataSelectionFixture(), ID()
	id, _, err := s.queueWAFCountryData(context.Background(), in, key, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"actor_id": u.ID, "payload_sha256": Hash(string(mustCountrySelection(t, in))), "selection": in})
	path, cookie := countryTestAPI+"/jobs/"+id+"/cancel-before-dispatch", login("waf-admin")
	// Both clients are nil: cancelling never loads repository data, checks an
	// installed cache or creates a native task.
	a.Executor, a.AppCatalog = nil, nil
	for _, origin := range []string{"", "https://foreign.invalid"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(string(body)))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 || countryWorkerState(t, s, id) != "queued" {
			t.Fatal("cancel route admitted missing CSRF or foreign origin", w.Code)
		}
	}
	for _, badBody := range []string{string(body[:len(body)-1]) + `,"source":"https://foreign.invalid"}`, string(body[:len(body)-1]) + `,"actor_id":"` + u.ID + `"}`, strings.Repeat(" ", 4097)} {
		if w := countryTestPost(t, a, path, cookie, key, badBody); w.Code != 400 || countryWorkerState(t, s, id) != "queued" {
			t.Fatal("cancel route accepted ambiguous or oversized body", w.Code, w.Body.String())
		}
	}
	for _, suffix := range []string{"?source=anything", "?id=" + id} {
		if w := countryTestPost(t, a, path+suffix, cookie, key, string(body)); w.Code != 400 {
			t.Fatal("cancel route accepted unbound query", w.Code)
		}
	}
	for range 2 {
		w := countryTestPost(t, a, path, cookie, key, string(body))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || countryWorkerState(t, s, id) != "cancelled" {
			t.Fatal("authenticated original cancellation failed", w.Code, w.Body.String())
		}
	}
	if w := wafTaskTestRead(a, countryTestAPI+"/requests/"+key, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"before_dispatch":true`) {
		t.Fatal("lost cancellation response cannot be read using original key", w.Code, w.Body.String())
	}
}

func mustCountrySelection(t *testing.T, in WAFCountryDataSelection) []byte {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
