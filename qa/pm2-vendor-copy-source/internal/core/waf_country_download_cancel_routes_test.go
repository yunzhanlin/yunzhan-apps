package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Actual authenticated HTTP and SQLite transactions, with an explicit synthetic
// Root transport. These tests do not claim a real native worker was stopped.
func countryDownloadCancelHTTPFixture(t *testing.T) (*Store, *Server, Job, wafCountryOriginal, WAFCountryDataOperation, func(string) *http.Cookie) {
	t.Helper()
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	id, _, err := s.queueWAFCountryData(context.Background(), countryDataSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil || j.ID != id {
		t.Fatal(j, err)
	}
	o, err := readWAFCountryOriginal(context.Background(), s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafCountryDispatchBoundary(context.Background(), j, true); err != nil {
		t.Fatal(err)
	}
	native := countryOperationFixture()
	native.JobID, native.ActorID, native.Selection, native.PayloadSHA = id, u.ID, o.Selection, o.PayloadSHA
	native.RequestedCachePlanSHA = WAFCountryCachePlanSHA(id, o.Selection)
	native.State, native.Error, native.Cache = "running", "", nil
	return s, a, j, o, native, login
}

func countryDownloadCancelBody(t *testing.T, o wafCountryOriginal, native WAFCountryDataOperation) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"actor_id": o.Actor, "payload_sha256": o.PayloadSHA, "request_sha256": native.RequestSHA, "selection": o.Selection})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func countryDownloadCancelRoot(t *testing.T, a *Server, o wafCountryOriginal, response func() []byte) *int {
	t.Helper()
	reads := new(int)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/waf/country/jobs/"+o.Job.ID || r.URL.RawQuery != WAFCountryObservationQuery(o.Actor, o.PayloadSHA).Encode() || r.ContentLength != 0 {
			t.Error("stop route issued a mutation or read another original", r.Method, r.URL.Path)
			return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		}
		*reads++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(response()))), Header: make(http.Header)}, nil
	})}}
	return reads
}

func TestWAFCountryDownloadCancelHTTPReadsOriginalAndAppendsOneIntentWithoutChangingTask(t *testing.T) {
	s, a, j, o, native, login := countryDownloadCancelHTTPFixture(t)
	raw, _ := json.Marshal(native)
	reads := countryDownloadCancelRoot(t, a, o, func() []byte { return raw })
	cookie := login("waf-admin")
	path := countryTestAPI + "/jobs/" + j.ID + "/download-cancellation"
	var before, after string
	q := `SELECT state||':'||payload||':'||idempotency_key||':'||steps||':'||error||':'||created_at||':'||updated_at FROM runtime_jobs WHERE id=?`
	if s.DB.QueryRow(q, j.ID).Scan(&before) != nil {
		t.Fatal("missing original")
	}
	w := wafTaskTestRead(a, path, cookie)
	var condition struct {
		CanRequest bool   `json:"can_request"`
		RequestSHA string `json:"request_sha256"`
		ReadOnly   bool   `json:"read_only"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &condition) != nil || !condition.CanRequest || !condition.ReadOnly || condition.RequestSHA != native.RequestSHA || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	var first WAFCountryDownloadCancellation
	for i := 0; i < 2; i++ {
		w = countryTestPost(t, a, path, cookie, "", countryDownloadCancelBody(t, o, native))
		var proof WAFCountryDownloadCancellation
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &proof) != nil || proof.JobID != j.ID || proof.RequestSHA != native.RequestSHA || proof.AutomaticReplayAllowed {
			t.Fatal(w.Code, w.Body.String())
		}
		if i == 0 {
			first = proof
		} else if proof != first {
			t.Fatal("repeat replaced original intent", proof, first)
		}
	}
	w = wafTaskTestRead(a, path, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &condition) != nil || condition.CanRequest {
		t.Fatal("original stop request was forgotten", w.Code, w.Body.String())
	}
	var intents int
	if *reads != 4 || s.DB.QueryRow(q, j.ID).Scan(&after) != nil || before != after || s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-download' AND target=?`, j.ID).Scan(&intents) != nil || intents != 1 {
		t.Fatal("HTTP changed original row, issued extra work or duplicated audit", *reads, intents)
	}
}

func TestWAFCountryDownloadCancelHTTPRefusesUnauthenticatedForeignAndChangedBindings(t *testing.T) {
	s, a, j, o, native, login := countryDownloadCancelHTTPFixture(t)
	raw, _ := json.Marshal(native)
	reads := countryDownloadCancelRoot(t, a, o, func() []byte { return raw })
	path := countryTestAPI + "/jobs/" + j.ID + "/download-cancellation"
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal("anonymous", w.Code)
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		cookie := login(name)
		if w := wafTaskTestRead(a, path, cookie); w.Code != 403 {
			t.Fatal(name, w.Code)
		}
		if w := countryTestPost(t, a, path, cookie, "", countryDownloadCancelBody(t, o, native)); w.Code != 403 {
			t.Fatal("restricted stop", name, w.Code)
		}
	}
	cookie := login("waf-admin")
	for _, suffix := range []string{"?", "?source=https://invalid.example/", "?request_sha256=" + native.RequestSHA} {
		if w := wafTaskTestRead(a, path+suffix, cookie); w.Code != 400 {
			t.Fatal("query", w.Code)
		}
		if w := countryTestPost(t, a, path+suffix, cookie, "", countryDownloadCancelBody(t, o, native)); w.Code != 400 {
			t.Fatal("query post", w.Code)
		}
	}
	for _, body := range []string{`{}`, `{"actor_id":"` + o.Actor + `","actor_id":"` + o.Actor + `"}`, strings.Repeat("x", 4097)} {
		if w := countryTestPost(t, a, path, cookie, "", body); w.Code != 400 {
			t.Fatal("shape", w.Code)
		}
	}
	for _, mode := range []string{"no-csrf", "foreign-origin"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(countryDownloadCancelBody(t, o, native)))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		if mode == "foreign-origin" {
			r.Header.Set("Origin", "https://foreign.invalid")
			u, err := s.sessionIdentity(Hash(cookie.Value), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("X-CSRF-Token", u.CSRF)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(mode, w.Code)
		}
	}
	if *reads != 0 {
		t.Fatal("rejected transport reached Root", *reads)
	}
	for _, mode := range []string{"actor", "payload", "request", "selection", "extra-field"} {
		var body map[string]any
		_ = json.Unmarshal([]byte(countryDownloadCancelBody(t, o, native)), &body)
		switch mode {
		case "actor":
			body["actor_id"] = ID()
		case "payload":
			body["payload_sha256"] = Hash("another payload")
		case "request":
			body["request_sha256"] = Hash("another request")
		case "selection":
			x := o.Selection
			x.Countries = []string{"US"}
			body["selection"] = x
		case "extra-field":
			body["signal"] = "SIGTERM"
		}
		b, _ := json.Marshal(body)
		w := countryTestPost(t, a, path, cookie, "", string(b))
		if w.Code != 400 && w.Code != 409 {
			t.Fatal("changed binding accepted", mode, w.Code)
		}
	}
	var intents int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-download'`).Scan(&intents) != nil || intents != 0 || countryWorkerState(t, s, j.ID) != "running" {
		t.Fatal("refused mutation changed original")
	}
}

func TestWAFCountryDownloadCancelHTTPRefusesUnknownRootAndCompletionRace(t *testing.T) {
	for _, mode := range []string{"queued", "succeeded", "foreign-root", "empty-root", "core-completed-during-observation"} {
		t.Run(mode, func(t *testing.T) {
			s, a, j, o, native, login := countryDownloadCancelHTTPFixture(t)
			response := native
			if mode == "queued" {
				response.State = "queued"
			}
			if mode == "succeeded" || mode == "core-completed-during-observation" {
				response = countryOperationFixture()
				response.JobID, response.ActorID, response.Selection, response.PayloadSHA = j.ID, o.Actor, o.Selection, o.PayloadSHA
				response.RequestedCachePlanSHA = WAFCountryCachePlanSHA(j.ID, o.Selection)
				response.Cache.OriginalJobID, response.Cache.PlanSHA = j.ID, response.RequestedCachePlanSHA
			}
			if mode == "foreign-root" {
				response.ActorID = ID()
			}
			countryDownloadCancelRoot(t, a, o, func() []byte {
				if mode == "empty-root" {
					return nil
				}
				if mode == "core-completed-during-observation" {
					b, _ := json.Marshal(response)
					if err := s.finishWAFCountryResult(context.Background(), j, b, o.Actor, o.Selection, nil); err != nil {
						t.Error(err)
					}
					b, _ = json.Marshal(native)
					return b
				}
				b, _ := json.Marshal(response)
				return b
			})
			w := countryTestPost(t, a, countryTestAPI+"/jobs/"+j.ID+"/download-cancellation", login("waf-admin"), "", countryDownloadCancelBody(t, o, native))
			if w.Code != 409 {
				t.Fatal("unproven or completed Root request adopted", w.Code, w.Body.String())
			}
			var intents int
			if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-download'`).Scan(&intents) != nil || intents != 0 {
				t.Fatal("rejected original retained stop intent")
			}
		})
	}
}
