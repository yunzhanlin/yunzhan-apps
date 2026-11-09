package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyticsHTMLQueueIdempotencyLongLaneAndImmutableFailures(t *testing.T) {
	s := testStore(t)
	id, err := s.QueueAnalyticsHTMLBuild("waf-build-one", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if repeat, err := s.QueueAnalyticsHTMLBuild("waf-build-one", "admin"); err != nil || repeat != id {
		t.Fatal("lost reply duplicated build", repeat, err)
	}
	if _, err := s.QueueAnalyticsHTMLBuild("waf-build-two", "admin"); err == nil {
		t.Fatal("parallel WAF build accepted")
	}
	if _, err := s.QueueSoftwareAction("website-analytics", "install", nil, "waf-build-one", "admin"); err == nil {
		t.Fatal("key reused for unrelated action")
	}
	if _, err := s.nextRuntimeControlJob(); err == nil {
		t.Fatal("long compile assigned to website/control worker")
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil || j.ID != id || j.Kind != "analytics_html_build" {
		t.Fatal(j, err)
	}
	if err := s.FinishRuntime(j, "owned failed build", []Step{{Time: Now(), Message: "failure evidence"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryRuntime(id, "admin"); err == nil {
		t.Fatal("failed immutable build reused")
	}
	var state, detail string
	if err := s.DB.QueryRow(`SELECT state,error FROM runtime_jobs WHERE id=?`, id).Scan(&state, &detail); err != nil || state != "failed" || detail != "owned failed build" {
		t.Fatal("original failure lost", state, detail, err)
	}
	if next, err := s.QueueAnalyticsHTMLBuild("waf-build-next", "admin"); err != nil || next == id {
		t.Fatal("new explicit build unavailable", next, err)
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='analytics.html.build' AND target=?`, id).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate audit", count)
	}
	if err := s.FinishRuntime(j, "", []Step{{Time: Now(), Message: "late success"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.updateAnalyticsHTMLSteps(id, []Step{{Time: Now(), Message: "late steps"}}); err != nil {
		t.Fatal(err)
	}
	var retained string
	if err := s.DB.QueryRow(`SELECT state,error,steps FROM runtime_jobs WHERE id=?`, id).Scan(&state, &detail, &retained); err != nil || state != "failed" || detail != "owned failed build" || !strings.Contains(retained, "failure evidence") || strings.Contains(retained, "late") {
		t.Fatal("late observer overwrote terminal evidence", state, detail, retained, err)
	}
}

func TestAnalyticsHTMLWorkerRequiresVerifiedProgramAndNeverRecordsRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, state, want      string
		verified, abi, wrongID bool
	}{{"ready", "ready", "succeeded", true, true, false}, {"ready-error", "ready", "needs_attention", true, true, false}, {"unverified", "ready", "needs_attention", false, true, false}, {"noABI", "ready", "needs_attention", true, false, false}, {"failed", "failed", "failed", false, false, false}, {"interrupted", "needs_attention", "needs_attention", false, false, false}, {"identity", "ready", "needs_attention", true, true, true}, {"unknown", "invented", "needs_attention", false, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			id, err := s.QueueAnalyticsHTMLBuild(ID(), "admin")
			if err != nil {
				t.Fatal(err)
			}
			j, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body string
				switch r.URL.Path {
				case "/v1/app-dependencies/website-analytics":
					body = `{"state":"ready"}`
				case "/v1/software/website-analytics/html-engine/build":
					var in map[string]string
					if json.NewDecoder(r.Body).Decode(&in) != nil || in["job_id"] != id || len(in) != 1 {
						t.Fatal("worker supplied arbitrary build input", in)
					}
					got := id
					if tc.wrongID {
						got = ID()
					}
					detail := "owned QA detail"
					if tc.name == "ready" {
						detail = ""
					}
					data, _ := json.Marshal(WAFEngineStatus{JobID: got, State: tc.state, IntegrityVerified: tc.verified, ABIValidated: tc.abi, BuildOnly: true, Error: detail, Steps: []Step{}})
					body = string(data)
				default:
					t.Fatal("unexpected generic runtime installer", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			runRuntimeJob(context.Background(), s, e, j)
			var state string
			s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state)
			if state != tc.want {
				t.Fatal(state, tc.want)
			}
			var count int
			s.DB.QueryRow(`SELECT count(*) FROM runtime_installations WHERE id='website-analytics'`).Scan(&count)
			if count != 0 {
				t.Fatal("build-only registered as installed runtime")
			}
		})
	}
}

func TestAnalyticsHTMLHTTPAdministratorMenuCSRFAndClosedInputs(t *testing.T) {
	s := testStore(t)
	for _, u := range []struct {
		name, role string
		menus      []string
	}{{"admin", "admin", nil}, {"limited", "admin", []string{"runtimes"}}, {"viewer", "viewer", nil}} {
		accessUser(t, s, u.name, u.role, u.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"entries":[],"build_only":true}`))}, nil
	})}}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", "http-build")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	base := "/api/software/website-analytics/"
	if w := request("POST", base+"html-engine/build", "{}", "", nil); w.Code != 401 {
		t.Fatal("anonymous", w.Code)
	}
	for _, name := range []string{"viewer", "limited", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if login.Code != 200 {
			t.Fatal(login.Body.String())
		}
		var auth accountSession
		json.Unmarshal(login.Body.Bytes(), &auth)
		cookie := login.Result().Cookies()[0]
		before := calls
		if w := request("POST", base+"html-engine/build", "{}", "", cookie); w.Code != 403 {
			t.Fatal("CSRF bypass", name, w.Code)
		}
		if name != "admin" {
			for _, operation := range []string{"html-engines", "html-engine/active", "html-engine/jobs/" + ID()} {
				if w := request("GET", base+operation, "", auth.CSRF, cookie); w.Code != 403 {
					t.Fatal(name, operation, w.Code)
				}
			}
			if w := request("POST", base+"html-engine/activate", `{"job_id":"`+ID()+`"}`, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized activation", name, w.Code)
			}
			if w := request("POST", base+"html-engine/jobs/"+ID()+"/cancel", "{}", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized cancellation", name, w.Code)
			}
			if w := request("POST", base+"html-engine/build", "{}", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("privileged builder call", name, w.Code)
			}
			continue
		}
		for _, body := range []string{`{"job_id":"untrusted"}`, `{"url":"https://example.com"}`, `{"flags":["shell"]}`, `{} {}`} {
			if w := request("POST", base+"html-engine/build", body, auth.CSRF, cookie); w.Code != 400 {
				t.Fatal("arbitrary build input", body, w.Code)
			}
		}
		w := request("POST", base+"html-engine/build", "{}", auth.CSRF, cookie)
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
		var queued map[string]string
		json.Unmarshal(w.Body.Bytes(), &queued)
		if w := request("GET", base+"html-engine/jobs/"+queued["job_id"], "", auth.CSRF, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"queued"`) || calls != before {
			t.Fatal("queued job requires nonexistent executor record", w.Code, w.Body.String())
		}
		if w := request("GET", base+"html-engines", "", auth.CSRF, cookie); w.Code != 200 || calls != before+1 {
			t.Fatal("authorized inventory", w.Code)
		}
		cancelPath := base + "html-engine/jobs/" + queued["job_id"] + "/cancel"
		if w := request("POST", cancelPath, "{}", "", cookie); w.Code != 403 {
			t.Fatal("cancel CSRF", w.Code)
		}
		for _, body := range []string{`{"signal":"KILL"}`, `{"unit":"nginx.service"}`, `{} {}`} {
			if w := request("POST", cancelPath, body, auth.CSRF, cookie); w.Code != 400 {
				t.Fatal("arbitrary cancellation", w.Code)
			}
		}
		if w := request("POST", base+"html-engine/jobs/"+ID()+"/cancel", "{}", auth.CSRF, cookie); w.Code != 409 {
			t.Fatal("unowned cancellation", w.Code)
		}
		a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != "POST" || r.URL.Path != "/v1/software/website-analytics/html-engine/jobs/"+queued["job_id"]+"/cancel" {
				t.Fatal("nonfixed cancel request", r.Method, r.URL.Path)
			}
			var in struct{}
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Fatal("cancel body")
			}
			data, _ := json.Marshal(WAFEngineStatus{JobID: queued["job_id"], State: "failed", Error: "administrator stopped", BuildOnly: true, Steps: []Step{}})
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
		})}}
		if w := request("POST", cancelPath, "{}", auth.CSRF, cookie); w.Code != 200 {
			t.Fatal("closed cancel", w.Code, w.Body.String())
		}
		if w := request("GET", base+"html-engine/jobs/"+queued["job_id"], "", auth.CSRF, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"failed"`) || !strings.Contains(w.Body.String(), "administrator stopped") {
			t.Fatal("cancel evidence", w.Code, w.Body.String())
		}
	}
}

func TestAnalyticsHTMLActivationOwnedBuildClosedInputAndActualAcknowledgment(t *testing.T) {
	s := testStore(t)
	accessUser(t, s, "admin", "admin", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"access-test-password-long"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", a.Config.Origin)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var auth accountSession
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	request := func(method, operation, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/software/website-analytics/html-engine/"+operation, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		out := httptest.NewRecorder()
		a.ServeHTTP(out, r)
		return out
	}
	id, err := s.QueueAnalyticsHTMLBuild(ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"job_id":"` + id + `"}`
	calls, reply := 0, "{}"
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/software/website-analytics/html-engine/activate" && r.URL.Path != "/v1/software/website-analytics/html-engine/active" {
			t.Fatal("unexpected executor endpoint", r.URL.Path)
		}
		if r.Method == "POST" {
			var in map[string]string
			if json.NewDecoder(r.Body).Decode(&in) != nil || len(in) != 1 || in["job_id"] != id {
				t.Fatal("arbitrary activation command", in)
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(reply))}, nil
	})}}
	if out := request("POST", "activate", body, ""); out.Code != 403 || calls != 0 {
		t.Fatal("activation CSRF", out.Code, calls)
	}
	for _, input := range []string{`{"job_id":"nginx.service"}`, `{"job_id":"` + id + `","sites":["all"]}`, body + ` {}`} {
		if out := request("POST", "activate", input, auth.CSRF); out.Code != 400 || calls != 0 {
			t.Fatal("open activation schema", input, out.Code, calls)
		}
	}
	if out := request("POST", "activate", `{"job_id":"`+ID()+`"}`, auth.CSRF); out.Code != 409 || calls != 0 {
		t.Fatal("unowned build", out.Code, calls)
	}
	for _, state := range []string{"queued", "running", "failed", "needs_attention"} {
		if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, state, id); err != nil {
			t.Fatal(err)
		}
		if out := request("POST", "activate", body, auth.CSRF); out.Code != 409 || calls != 0 {
			t.Fatal("unverified persistent build", state, out.Code, calls)
		}
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded',kind='waf_engine_build' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if out := request("POST", "activate", body, auth.CSRF); out.Code != 409 || calls != 0 {
		t.Fatal("unrelated successful build", out.Code, calls)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET kind='analytics_html_build' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		`{}`, `{"job_id":"` + id + `","active":true}`, `{"job_id":"` + id + `","active":true,"worker_acknowledged":true}`,
		`{"job_id":"` + ID() + `","active":true,"worker_acknowledged":true,"site_auto_injection":false}`,
		`{"job_id":"` + id + `","active":true,"worker_acknowledged":true,"site_auto_injection":true}`,
		`{"job_id":"` + id + `","active":false,"worker_acknowledged":true,"site_auto_injection":false}`,
	} {
		reply = malformed
		if out := request("POST", "activate", body, auth.CSRF); out.Code != 503 {
			t.Fatal("forged/missing acknowledgment accepted", malformed, out.Code, out.Body.String())
		}
	}
	var audits int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='analytics.html.activate'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("unverified loading recorded as success", audits, err)
	}
	reply = `{"job_id":"` + id + `","active":true,"worker_acknowledged":true,"site_auto_injection":false}`
	if out := request("POST", "activate", body, auth.CSRF); out.Code != 200 {
		t.Fatal("verified owned activation", out.Code, out.Body.String())
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='analytics.html.activate' AND target=? AND result='worker-acknowledged'`, id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("verified activation audit missing", audits, err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER deny_html_activate_audit BEFORE INSERT ON audit_logs WHEN NEW.action='analytics.html.activate' BEGIN SELECT RAISE(ABORT,'QA unavailable audit'); END`); err != nil {
		t.Fatal(err)
	}
	if out := request("POST", "activate", body, auth.CSRF); out.Code != 503 || !strings.Contains(out.Body.String(), "审计保存失败") {
		t.Fatal("lost audit was reported as success", out.Code, out.Body.String())
	}
	for _, malformed := range []string{`{}`, `{"state":"not-activated"}`, `{"active":false,"state":"unknown"}`, `{"active":true,"state":"active","job_id":"` + id + `"}`, `{"active":true,"state":"ready","worker_acknowledged":true,"job_id":"` + id + `"}`, `{"active":false,"state":"not-activated","worker_acknowledged":true}`} {
		reply = malformed
		if out := request("GET", "active", "", auth.CSRF); out.Code != 503 {
			t.Fatal("unverified active inventory accepted", malformed, out.Code)
		}
	}
	for _, valid := range []string{`{"active":false,"state":"not-activated"}`, `{"active":false,"state":"needs-attention","error":"stale worker"}`, `{"active":true,"state":"active","job_id":"` + id + `","worker_acknowledged":true}`} {
		reply = valid
		if out := request("GET", "active", "", auth.CSRF); out.Code != 200 {
			t.Fatal("verified active inventory denied", valid, out.Code, out.Body.String())
		}
	}
}
