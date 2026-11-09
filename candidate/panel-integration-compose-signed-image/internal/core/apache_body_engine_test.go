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

func TestApacheBodyEngineQueueIdempotencyLongLaneAndImmutableFailures(t *testing.T) {
	s := testStore(t)
	id, err := s.QueueApacheBodyEngineBuild("waf-build-one", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if repeat, err := s.QueueApacheBodyEngineBuild("waf-build-one", "admin"); err != nil || repeat != id {
		t.Fatal("lost reply duplicated build", repeat, err)
	}
	if _, err := s.QueueApacheBodyEngineBuild("waf-build-two", "admin"); err == nil {
		t.Fatal("parallel WAF build accepted")
	}
	if _, err := s.QueueSoftwareAction("apache-waf", "install", nil, "waf-build-one", "admin"); err == nil {
		t.Fatal("key reused for unrelated action")
	}
	if _, err := s.nextRuntimeControlJob(); err == nil {
		t.Fatal("long compile assigned to website/control worker")
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil || j.ID != id || j.Kind != "apache_body_build" {
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
	if next, err := s.QueueApacheBodyEngineBuild("waf-build-next", "admin"); err != nil || next == id {
		t.Fatal("new explicit build unavailable", next, err)
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='apache.body.engine.build' AND target=?`, id).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate audit", count)
	}
	if err := s.FinishRuntime(j, "", []Step{{Time: Now(), Message: "late success"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.updateApacheBodyEngineSteps(id, []Step{{Time: Now(), Message: "late steps"}}); err != nil {
		t.Fatal(err)
	}
	var retained string
	if err := s.DB.QueryRow(`SELECT state,error,steps FROM runtime_jobs WHERE id=?`, id).Scan(&state, &detail, &retained); err != nil || state != "failed" || detail != "owned failed build" || !strings.Contains(retained, "failure evidence") || strings.Contains(retained, "late") {
		t.Fatal("late observer overwrote terminal evidence", state, detail, retained, err)
	}
}

func TestApacheBodyEngineWorkerRequiresVerifiedProgramAndNeverRecordsRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, state, want      string
		verified, abi, wrongID bool
	}{{"ready", "ready", "succeeded", true, true, false}, {"historical-ready", "ready", "needs_attention", true, true, false}, {"retained", "retained_unsupported", "needs_attention", false, false, false}, {"ready-error", "ready", "needs_attention", true, true, false}, {"unverified", "ready", "needs_attention", false, true, false}, {"noABI", "ready", "needs_attention", true, false, false}, {"noHardening", "ready", "needs_attention", true, true, false}, {"compilerAlive", "ready", "needs_attention", true, true, false}, {"failed", "failed", "failed", false, false, false}, {"interrupted", "needs_attention", "needs_attention", false, false, false}, {"identity", "ready", "needs_attention", true, true, true}, {"unknown", "invented", "needs_attention", false, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			id, err := s.QueueApacheBodyEngineBuild(ID(), "admin")
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
				case "/v1/app-dependencies/apache-waf":
					body = `{"state":"ready"}`
				case "/v1/software/apache-waf/body-engine/build":
					var in map[string]string
					if json.NewDecoder(r.Body).Decode(&in) != nil || in["job_id"] != id || len(in) != 1 {
						t.Fatal("worker supplied arbitrary build input", in)
					}
					got := id
					if tc.wrongID {
						got = ID()
					}
					detail := "owned QA detail"
					if tc.state == "ready" && tc.name != "ready-error" {
						detail = ""
					}
					data, _ := json.Marshal(ApacheBodyEngineStatus{JobID: got, State: tc.state, IntegrityVerified: tc.verified, ABIValidated: tc.abi, HardeningValidated: tc.name != "noHardening", CompilerCollected: tc.name != "compilerAlive", HistoricalIntegrityVerified: tc.name == "historical-ready" || tc.name == "retained", BuildOnly: true, Error: detail, Steps: []Step{}})
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
			s.DB.QueryRow(`SELECT count(*) FROM runtime_installations WHERE id='apache-waf'`).Scan(&count)
			if count != 0 {
				t.Fatal("build-only registered as installed runtime")
			}
		})
	}
}

func TestApacheBodyEngineHTTPAdministratorMenuCSRFAndClosedInputs(t *testing.T) {
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
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"entries":[]}`))}, nil
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
	base := "/api/software/apache-waf/"
	if w := request("POST", base+"body-engine/build", "{}", "", nil); w.Code != 401 {
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
		if w := request("POST", base+"body-engine/build", "{}", "", cookie); w.Code != 403 {
			t.Fatal("CSRF bypass", name, w.Code)
		}
		if name != "admin" {
			for _, operation := range []string{"body-engines", "body-engine/jobs/" + ID()} {
				if w := request("GET", base+operation, "", auth.CSRF, cookie); w.Code != 403 {
					t.Fatal(name, operation, w.Code)
				}
			}
			if w := request("POST", base+"body-engine/jobs/"+ID()+"/cancel", "{}", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized cancellation", name, w.Code)
			}
			if w := request("POST", base+"body-engine/build", "{}", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("privileged builder call", name, w.Code)
			}
			continue
		}
		for _, body := range []string{`{"job_id":"untrusted"}`, `{"url":"https://example.com"}`, `{"flags":["shell"]}`, `{} {}`} {
			if w := request("POST", base+"body-engine/build", body, auth.CSRF, cookie); w.Code != 400 {
				t.Fatal("arbitrary build input", body, w.Code)
			}
		}
		w := request("POST", base+"body-engine/build", "{}", auth.CSRF, cookie)
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
		var queued map[string]string
		json.Unmarshal(w.Body.Bytes(), &queued)
		if w := request("GET", base+"body-engine/jobs/"+queued["job_id"], "", auth.CSRF, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"queued"`) || calls != before {
			t.Fatal("queued job requires nonexistent executor record", w.Code, w.Body.String())
		}
		if w := request("GET", base+"body-engines", "", auth.CSRF, cookie); w.Code != 200 || calls != before+1 {
			t.Fatal("authorized inventory", w.Code)
		}
		cancelPath := base + "body-engine/jobs/" + queued["job_id"] + "/cancel"
		if w := request("POST", cancelPath, "{}", "", cookie); w.Code != 403 {
			t.Fatal("cancel CSRF", w.Code)
		}
		for _, body := range []string{`{"signal":"KILL"}`, `{"unit":"nginx.service"}`, `{} {}`} {
			if w := request("POST", cancelPath, body, auth.CSRF, cookie); w.Code != 400 {
				t.Fatal("arbitrary cancellation", w.Code)
			}
		}
		if w := request("POST", base+"body-engine/jobs/"+ID()+"/cancel", "{}", auth.CSRF, cookie); w.Code != 409 {
			t.Fatal("unowned cancellation", w.Code)
		}
		for _, defect := range []string{"empty-failure", "wrong-id", "not-build-only", "running", "no-integrity", "no-abi", "no-hardening", "compiler-alive", "ready-error"} {
			result := ApacheBodyEngineStatus{JobID: queued["job_id"], State: "ready", BuildOnly: true, IntegrityVerified: true, ABIValidated: true, HardeningValidated: true, CompilerCollected: true, Steps: []Step{}}
			switch defect {
			case "empty-failure":
				result.State = "failed"
			case "wrong-id":
				result.JobID = ID()
			case "not-build-only":
				result.BuildOnly = false
			case "running":
				result.State = "running"
			case "no-integrity":
				result.IntegrityVerified = false
			case "no-abi":
				result.ABIValidated = false
			case "no-hardening":
				result.HardeningValidated = false
			case "compiler-alive":
				result.CompilerCollected = false
			case "ready-error":
				result.Error = "unresolved"
			}
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				data, _ := json.Marshal(result)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
			})}}
			if w := request("POST", cancelPath, "{}", auth.CSRF, cookie); w.Code != 503 {
				t.Fatal("unverified cancellation accepted", defect, w.Code, w.Body.String())
			}
			var state, detail string
			if err := s.DB.QueryRow(`SELECT state,error FROM runtime_jobs WHERE id=?`, queued["job_id"]).Scan(&state, &detail); err != nil || state != "queued" || detail != "" {
				t.Fatal("unverified cancellation changed persistent evidence", defect, state, detail, err)
			}
		}
		a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != "POST" || r.URL.Path != "/v1/software/apache-waf/body-engine/jobs/"+queued["job_id"]+"/cancel" {
				t.Fatal("nonfixed cancel request", r.Method, r.URL.Path)
			}
			var in struct{}
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Fatal("cancel body")
			}
			data, _ := json.Marshal(ApacheBodyEngineStatus{JobID: queued["job_id"], State: "failed", Error: "administrator stopped", BuildOnly: true, Steps: []Step{}})
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
		})}}
		if w := request("POST", cancelPath, "{}", auth.CSRF, cookie); w.Code != 200 {
			t.Fatal("closed cancel", w.Code, w.Body.String())
		}
		if w := request("GET", base+"body-engine/jobs/"+queued["job_id"], "", auth.CSRF, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"failed"`) || !strings.Contains(w.Body.String(), "administrator stopped") {
			t.Fatal("cancel evidence", w.Code, w.Body.String())
		}
	}
}
