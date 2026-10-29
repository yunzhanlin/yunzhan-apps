package core

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWAFCountryIssuedCancellationOnlyAppendsBoundStopRequest(t *testing.T) {
	s, j, o, out := countryWorkerFixture(t)
	ctx := context.Background()
	if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err != nil {
		t.Fatal(err)
	}
	var rowBefore, rowAfter string
	query := `SELECT id||':'||state||':'||payload||':'||idempotency_key||':'||steps||':'||error||':'||created_at||':'||updated_at FROM runtime_jobs WHERE id=?`
	if s.DB.QueryRow(query, j.ID).Scan(&rowBefore) != nil {
		t.Fatal("missing original running row")
	}
	if requested, err := s.WAFCountryDownloadCancellationNative(ctx, j.ID, o.Actor, o.PayloadSHA, out.RequestSHA); err != nil || requested {
		t.Fatal("missing stop intent became cancellation authority", requested, err)
	}
	proof, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection)
	if err != nil || proof.JobID != j.ID || proof.ActorID != o.Actor || proof.PayloadSHA != o.PayloadSHA || proof.RequestSHA != out.RequestSHA || proof.AutomaticReplayAllowed {
		t.Fatal(proof, err)
	}
	if s.DB.QueryRow(query, j.ID).Scan(&rowAfter) != nil || rowAfter != rowBefore {
		t.Fatal("stop request relabelled, requeued or changed the original job")
	}
	for range 3 {
		again, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection)
		if err != nil || !reflect.DeepEqual(again, proof) {
			t.Fatal("same request replaced its original time/binding", again, err)
		}
	}
	if requested, err := s.WAFCountryDownloadCancellationNative(ctx, j.ID, o.Actor, o.PayloadSHA, out.RequestSHA); err != nil || !requested {
		t.Fatal("fixed original worker could not read stop-only proof", requested, err)
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*)FROM audit_logs WHERE action='waf.country.cancel-download'AND target=?`, j.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("duplicate stop requests were appended")
	}
	if _, err := s.cancelWAFCountryBeforeDispatch(ctx, o.Actor, j.ID, o.PayloadSHA, o.Selection); err == nil || countryWorkerState(t, s, j.ID) != "running" {
		t.Fatal("issued stop request became a before-dispatch cancellation")
	}
	if s.CheckWAFCountryUpgrade(ctx) == nil {
		t.Fatal("a stop request was treated as a completed task")
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer'WHERE user_id=?`, o.Actor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection); err == nil {
		t.Fatal("revoked account issued another stop request")
	}
	if requested, err := s.WAFCountryDownloadCancellationNative(ctx, j.ID, o.Actor, o.PayloadSHA, out.RequestSHA); err != nil || !requested {
		t.Fatal("revocation erased a historically authorized stop-only request", requested, err)
	}
	if s.ValidateWAFCountryDataNative(ctx, j.ID, o.Actor, o.PayloadSHA) == nil {
		t.Fatal("historical cancellation granted fresh download authority")
	}
}

func TestWAFCountryIssuedCancellationRejectsAbsentDispatchForeignBindingAndClosedResults(t *testing.T) {
	for _, mode := range []string{"no-dispatch", "foreign-actor", "wrong-payload", "wrong-request", "different-selection", "terminal", "present-result", "duplicate-dispatch", "missing-menu"} {
		t.Run(mode, func(t *testing.T) {
			s, j, o, out := countryWorkerFixture(t)
			ctx := context.Background()
			if mode != "no-dispatch" {
				if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err != nil {
					t.Fatal(err)
				}
			}
			actor, payload, request, selection := o.Actor, o.PayloadSHA, out.RequestSHA, o.Selection
			var err error
			switch mode {
			case "foreign-actor":
				actor = accessUser(t, s, "other-stop-owner", "admin", []string{"runtimes", "security"}).ID
			case "wrong-payload":
				payload = strings.Repeat("a", 64)
			case "wrong-request":
				request = "not-a-request-digest"
			case "different-selection":
				selection.Countries = []string{"US"}
			case "terminal":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='original failure'WHERE id=?`, j.ID)
			case "present-result":
				raw, _ := json.Marshal(out)
				err = s.finishWAFCountryResult(ctx, j, raw, o.Actor, o.Selection, nil)
			case "duplicate-dispatch":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'waf.country.dispatch',?,?,?)`, o.Actor, j.ID, o.PayloadSHA, Now())
			case "missing-menu":
				_, err = s.DB.Exec(`UPDATE app_user_roles SET role='viewer'WHERE user_id=?`, o.Actor)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := countryWorkerState(t, s, j.ID)
			if _, err := s.requestWAFCountryDownloadCancellation(ctx, actor, j.ID, payload, request, selection); err == nil || countryWorkerState(t, s, j.ID) != before {
				t.Fatal("changed or closed original was adopted", mode, err)
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*)FROM audit_logs WHERE action='waf.country.cancel-download'`).Scan(&count) != nil || count != 0 {
				t.Fatal("refused request retained partial stop evidence")
			}
		})
	}
}

func TestWAFCountryIssuedCancellationCorruptionNeverSignalsOrRepairs(t *testing.T) {
	for _, mode := range []string{"actor", "payload", "request", "duplicate", "stamp", "dispatch", "dispatch-time", "queued", "closed", "late-result"} {
		t.Run(mode, func(t *testing.T) {
			s, j, o, out := countryWorkerFixture(t)
			ctx := context.Background()
			if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err != nil {
				t.Fatal(err)
			}
			if _, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "actor":
				_, err = s.DB.Exec(`UPDATE audit_logs SET actor=? WHERE action='waf.country.cancel-download'`, ID())
			case "payload":
				_, err = s.DB.Exec(`UPDATE audit_logs SET result=? WHERE action='waf.country.cancel-download'`, Hash("changed")+":"+out.RequestSHA)
			case "request":
				_, err = s.DB.Exec(`UPDATE audit_logs SET result=? WHERE action='waf.country.cancel-download'`, o.PayloadSHA+":"+Hash("another original request"))
			case "duplicate":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at)SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='waf.country.cancel-download'`)
			case "stamp":
				_, err = s.DB.Exec(`UPDATE audit_logs SET created_at='2000-01-01T00:00:00Z'WHERE action='waf.country.cancel-download'`)
			case "dispatch":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE action='waf.country.dispatch'`)
			case "dispatch-time":
				_, err = s.DB.Exec(`UPDATE audit_logs SET created_at='2099-01-01T00:00:00Z' WHERE action='waf.country.dispatch'`)
			case "queued":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state='queued' WHERE id=?`, j.ID)
			case "closed":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='original closed'WHERE id=?`, j.ID)
			case "late-result":
				raw, _ := json.Marshal(out)
				err = s.finishWAFCountryResult(ctx, j, raw, o.Actor, o.Selection, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if requested, err := s.WAFCountryDownloadCancellationNative(ctx, j.ID, o.Actor, o.PayloadSHA, out.RequestSHA); err == nil || requested {
				t.Fatal("inconsistent or closed stop request became worker authority", mode, requested, err)
			}
		})
	}
}

func TestWAFCountryIssuedCancellationSettlesOnlyCompleteBoundRootResults(t *testing.T) {
	for _, mode := range []string{"cancelled", "commit-won", "ordinary-failure", "revoked-after-intent", "wrong-root-request", "missing-intent"} {
		t.Run(mode, func(t *testing.T) {
			s, j, o, out := countryWorkerFixture(t)
			ctx := context.Background()
			if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err != nil {
				t.Fatal(err)
			}
			if mode != "missing-intent" {
				if _, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "commit-won" {
				out.State, out.Error, out.Cache = "failed", WAFCountryDownloadCancelledMessage, nil
			}
			if mode == "ordinary-failure" {
				out.Error = "original source read failed before cancellation took effect"
			}
			if mode == "revoked-after-intent" {
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, o.Actor); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "wrong-root-request" {
				out.RequestSHA = Hash("a different sealed original")
			}
			raw, _ := json.Marshal(out)
			err := s.finishWAFCountryResult(ctx, j, raw, o.Actor, o.Selection, nil)
			if mode == "missing-intent" || mode == "wrong-root-request" {
				if err == nil || countryWorkerState(t, s, j.ID) != "running" {
					t.Fatal("unbound cancellation became a closed result", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := readWAFCountryOriginal(ctx, s.DB, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			detail, err := countryRequestDetail(ctx, s.DB, original)
			if err != nil || detail.DownloadCancellation == nil || detail.Result == nil || !reflect.DeepEqual(*detail.Result, out) || detail.ResultSHA != Hash(string(raw)) {
				t.Fatal("original outcome or cancellation was discarded", detail, err)
			}
			if mode != "commit-won" && s.ValidateWAFCountryFailedNative(ctx, out) != nil {
				t.Fatal("complete original failed unit lost historical closure")
			}
			if mode == "revoked-after-intent" {
				if s.ValidateWAFCountryDataNative(ctx, j.ID, o.Actor, o.PayloadSHA) == nil {
					t.Fatal("completed stop request granted a new download")
				}
			}
			// A late competing result cannot overwrite this original terminal.
			out.State, out.Error, out.Cache = "failed", "late competing result", nil
			late, _ := json.Marshal(out)
			if err := s.finishWAFCountryResult(ctx, j, late, o.Actor, o.Selection, nil); err != nil {
				t.Fatal(err)
			}
			var digest string
			if s.DB.QueryRow(`SELECT result_sha256 FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&digest) != nil || digest != Hash(string(raw)) {
				t.Fatal("late result replaced the original")
			}
		})
	}
}

func TestWAFCountryIssuedCancellationMissingRootReceiptCannotCloseBrowserOrUpgrade(t *testing.T) {
	s, j, o, out := countryWorkerFixture(t)
	ctx := context.Background()
	if _, err := s.wafCountryDispatchBoundary(ctx, j, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.requestWAFCountryDownloadCancellation(ctx, o.Actor, j.ID, o.PayloadSHA, out.RequestSHA, o.Selection); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error=? WHERE id=?`, WAFCountryDownloadCancelledMessage, j.ID); err != nil {
		t.Fatal(err)
	}
	original, err := readWAFCountryOriginal(ctx, s.DB, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := countryRequestDetail(ctx, s.DB, original); err == nil {
		t.Fatal("missing Root receipt was reported as stopped")
	}
	if s.CheckWAFCountryUpgrade(ctx) == nil {
		t.Fatal("incomplete cancellation was accepted as closed during upgrade")
	}
}
