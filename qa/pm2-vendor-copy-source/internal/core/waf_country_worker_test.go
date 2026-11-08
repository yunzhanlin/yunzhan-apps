package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
)

// SQLite and HTTP transport fixtures ONLY. These unsigned synthetic responses
// do not prove installed app authority, provider signatures or actual Root I/O.
func countryWorkerFixture(t *testing.T) (*Store, Job, wafCountryOriginal, WAFCountryDataOperation) {
	t.Helper()
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in := countryDataSelectionFixture()
	id, _, err := s.queueWAFCountryData(context.Background(), in, ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := s.nextRuntimeControlJob(); err == nil || other.ID != "" {
		t.Fatal("country network task entered the website control worker", other, err)
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil || j.ID != id {
		t.Fatal("country task did not enter bounded installation/data worker", j, err)
	}
	original, err := readWAFCountryOriginal(context.Background(), s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	out := countryOperationFixture()
	out.JobID, out.ActorID, out.Selection, out.PayloadSHA = id, u.ID, in, original.PayloadSHA
	out.RequestedCachePlanSHA = WAFCountryCachePlanSHA(id, in)
	out.Cache.OriginalJobID, out.Cache.PlanSHA = id, out.RequestedCachePlanSHA
	return s, j, original, out
}

func countryWorkerState(t *testing.T, s *Store, id string) string {
	t.Helper()
	var state string
	if err := s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestWAFCountryWorkerLostPostAcknowledgementOnlyObservesOriginalAndPersistsWholeResult(t *testing.T) {
	s, j, original, out := countryWorkerFixture(t)
	var posts, gets atomic.Int32
	encoded, _ := json.Marshal(out)
	resultRaw := append(encoded, '\n')
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/waf/country/jobs/"+j.ID {
			t.Error("foreign original endpoint", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		if r.Method == "POST" {
			posts.Add(1)
			raw, err := io.ReadAll(r.Body)
			var body struct {
				Actor     string                     `json:"actor_id"`
				Selection WAFCountryDataSelection    `json:"selection"`
				Envelope  appcatalog.GeoDataEnvelope `json:"envelope"`
			}
			if err != nil || json.Unmarshal(raw, &body) != nil || body.Actor != original.Actor || !SameWAFCountryDataSelection(body.Selection, original.Selection) || r.URL.RawQuery != "" {
				t.Error("original complete submission changed")
			}
			var count int
			if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, j.ID).Scan(&count) != nil || count != 1 {
				t.Error("Root POST preceded durable unique dispatch intent")
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close() // Original action may have occurred; NO second POST.
			return
		}
		gets.Add(1)
		if r.Method != "GET" || r.URL.Query().Get("actor_id") != original.Actor || r.URL.Query().Get("payload_sha256") != original.PayloadSHA || len(r.URL.Query()) != 2 {
			t.Error("original read-only observation changed")
		}
		_, _ = w.Write(resultRaw)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runWAFCountryOriginal(ctx, ctx, s, countryWorkerClient(server), j, original, appcatalog.GeoDataEnvelope{})
	if posts.Load() != 1 || gets.Load() != 1 || countryWorkerState(t, s, j.ID) != "succeeded" {
		t.Fatal("lost original POST acknowledgement caused replay or a false terminal", posts.Load(), gets.Load(), countryWorkerState(t, s, j.ID))
	}
	var body []byte
	var digest string
	if s.DB.QueryRow(`SELECT body,result_sha256 FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&body, &digest) != nil || !bytes.Equal(body, resultRaw) || digest != Hash(string(resultRaw)) {
		t.Fatal("complete original Root wire response was not preserved byte-for-byte")
	}
}

type countryWorkerTransport func(*http.Request) (*http.Response, error)

func (f countryWorkerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func countryWorkerClient(server *httptest.Server) *ExecutorClient {
	return &ExecutorClient{Client: &http.Client{Transport: countryWorkerTransport(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return server.Client().Transport.RoundTrip(r)
	})}}
}

func TestWAFCountryWorkerRestartAndLateRevocationCannotSubmitOrFetchAgain(t *testing.T) {
	s, j, original, out := countryWorkerFixture(t)
	if prior, err := s.wafCountryDispatchBoundary(context.Background(), j, true); err != nil || prior {
		t.Fatal(prior, err)
	}
	if err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	restarted, err := s.nextRuntimeInstallJob()
	if err != nil || restarted.ID != j.ID || restarted.Payload != j.Payload {
		t.Fatal("restart changed original", restarted, err)
	}
	if _, err := s.DB.Exec(`DELETE FROM app_user_roles WHERE user_id=?`, original.Actor); err != nil {
		t.Fatal(err)
	}
	var gets, sourceGets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/waf/country/jobs/"+j.ID {
			t.Error("restart replayed Root work", r.Method, r.URL)
			w.WriteHeader(400)
			return
		}
		gets.Add(1)
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceGets.Add(1)
		w.WriteHeader(503)
	}))
	defer source.Close()
	repo := &appcatalog.Client{BaseURL: source.URL, PublicKey: appcatalog.Default().PublicKey, HTTP: source.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runWAFCountryDataJob(ctx, s, countryWorkerClient(server), restarted, repo)
	if gets.Load() != 1 || sourceGets.Load() != 0 || countryWorkerState(t, s, j.ID) != "succeeded" {
		t.Fatal("original restarted observation replayed/fetched or failed", gets.Load(), sourceGets.Load(), countryWorkerState(t, s, j.ID))
	}
	var count int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, j.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("restart replaced original dispatch")
	}
}

func TestWAFCountryWorkerMalformedForeignActiveOrOversizeRepliesStayUncertainWithoutReplay(t *testing.T) {
	for _, kind := range []string{"actor", "active", "alias", "duplicate", "empty", "oversize", "changed-request"} {
		t.Run(kind, func(t *testing.T) {
			s, j, _, out := countryWorkerFixture(t)
			if _, err := s.wafCountryDispatchBoundary(context.Background(), j, true); err != nil {
				t.Fatal(err)
			}
			var gets, posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					posts.Add(1)
					w.WriteHeader(400)
					return
				}
				attempt := gets.Add(1)
				v := out
				switch kind {
				case "actor":
					v.ActorID = ID()
				case "active":
					v.Cache.ActivatedNginxPolicy = true
				case "changed-request":
					if attempt == 1 {
						v.State, v.Cache = "running", nil
					} else {
						v.RequestSHA = Hash("foreign second original seal")
					}
				}
				raw, _ := json.Marshal(v)
				switch kind {
				case "alias":
					raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"Format":1`), 1)
				case "duplicate":
					raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
				case "empty":
					raw = []byte(`{}`)
				case "oversize":
					raw = append(raw, bytes.Repeat([]byte(" "), 32<<10)...)
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			runWAFCountryDataJob(ctx, s, countryWorkerClient(server), j, appcatalog.Default())
			var results int
			if posts.Load() != 0 || countryWorkerState(t, s, j.ID) != "needs_attention" || s.DB.QueryRow(`SELECT count(*) FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&results) != nil || results != 0 {
				t.Fatal("unqualified reply accepted or original POST replayed", kind, posts.Load(), gets.Load(), results)
			}
		})
	}
}

func TestWAFCountryWholeResultAndTerminalAreAtomicAndNeverOverwriteOriginalFailure(t *testing.T) {
	s, j, original, out := countryWorkerFixture(t)
	out.State, out.Error, out.Cache = "failed", "original synthetic transfer failure", nil
	raw, _ := json.Marshal(out)
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_country_result_audit BEFORE INSERT ON audit_logs WHEN NEW.action='waf.country.result' BEGIN SELECT RAISE(ABORT,'explicit atomic-result fixture');END;`); err != nil {
		t.Fatal(err)
	}
	if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err == nil {
		t.Fatal("injected terminal audit failure disappeared")
	}
	var count int
	if countryWorkerState(t, s, j.ID) != "running" || s.DB.QueryRow(`SELECT count(*) FROM waf_country_results`).Scan(&count) != nil || count != 0 {
		t.Fatal("partially persisted result survived transaction rollback")
	}
	if _, err := s.DB.Exec(`DROP TRIGGER refuse_country_result_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err != nil {
		t.Fatal(err)
	}
	late := out
	late.State, late.Error = "needs_attention", "late foreign failure must not replace history"
	late.RequestSHA = Hash("different late original")
	laterRaw, _ := json.Marshal(late)
	if err := s.finishWAFCountryResult(context.Background(), j, laterRaw, original.Actor, original.Selection, nil); err != nil {
		t.Fatal(err)
	}
	var body []byte
	var digest, detail string
	if s.DB.QueryRow(`SELECT body,result_sha256 FROM waf_country_results WHERE job_id=?`, j.ID).Scan(&body, &digest) != nil || !bytes.Equal(body, raw) || digest != Hash(string(raw)) || countryWorkerState(t, s, j.ID) != "failed" || s.DB.QueryRow(`SELECT error FROM runtime_jobs WHERE id=?`, j.ID).Scan(&detail) != nil || detail != out.Error {
		t.Fatal("late observation changed original complete failure")
	}
	if err := s.RetryRuntime(j.ID, original.Actor); err == nil {
		t.Fatal("generic retry overwrote original country task")
	}
}

func TestWAFCountryUnavailableSignedSourceCannotCommitIntentOrCallRoot(t *testing.T) {
	s, j, _, _ := countryWorkerFixture(t)
	var rootCalls atomic.Int32
	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootCalls.Add(1)
		w.WriteHeader(503)
	}))
	defer root.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer source.Close()
	repo := &appcatalog.Client{BaseURL: source.URL, PublicKey: appcatalog.Default().PublicKey, HTTP: source.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runWAFCountryDataJob(ctx, s, countryWorkerClient(root), j, repo)
	var count int
	if rootCalls.Load() != 0 || countryWorkerState(t, s, j.ID) != "failed" || s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.dispatch'`).Scan(&count) != nil || count != 0 {
		t.Fatal("unverified/unavailable repository reached original Root boundary", rootCalls.Load(), count)
	}
}

func TestWAFCountryRootRedirectCannotReplayPostOrChangeOriginalEndpoint(t *testing.T) {
	s, j, original, out := countryWorkerFixture(t)
	var posts, redirected, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "redirected=yes" {
			redirected.Add(1)
			w.WriteHeader(400)
			return
		}
		if r.Method == "POST" {
			posts.Add(1)
			w.Header().Set("Location", "/v1/waf/country/jobs/"+j.ID+"?redirected=yes")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		gets.Add(1)
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runWAFCountryOriginal(ctx, ctx, s, countryWorkerClient(server), j, original, appcatalog.GeoDataEnvelope{})
	if posts.Load() != 1 || redirected.Load() != 0 || gets.Load() != 1 || countryWorkerState(t, s, j.ID) != "succeeded" {
		t.Fatal("Root redirect changed/replayed original control request", posts.Load(), redirected.Load(), gets.Load())
	}
}
