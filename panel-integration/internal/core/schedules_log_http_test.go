package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogCleanupInspectionHTTPUsesMenuPermissionsAndImmutableRunSite(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"admin", "viewer", "operator"} {
		accessUser(t, s, role, role, nil)
	}
	accessUser(t, s, "no-menu", "admin", []string{"sites"})
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	wrongIdentity := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/sites/"+schedule.TargetID+"/logs/operations/"+run.ID {
			t.Fatalf("caller controlled path %s %s", r.Method, r.URL.Path)
		}
		out := LogCleanupInspection{RequestID: run.ID, SiteID: schedule.TargetID, State: "not_recorded", Files: []LogCleanupFileInspection{}, ReadOnly: true}
		if wrongIdentity {
			out.SiteID = ID()
		}
		body, e := json.Marshal(out)
		if e != nil {
			t.Fatal(e)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}}
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	path := "/api/schedules/runs/" + run.ID + "/log-cleanup"
	if w := request("GET", path, "", nil); w.Code != 401 || calls != 0 {
		t.Fatal(w.Code, calls)
	}
	for _, role := range []string{"viewer", "operator", "no-menu", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+role+`","password":"access-test-password-long"}`, nil)
		if login.Code != 200 {
			t.Fatal(role, login.Code, login.Body.String())
		}
		cookie := login.Result().Cookies()[0]
		before := calls
		w := request("GET", path, "", cookie)
		if role != "admin" {
			if w.Code != 403 || calls != before {
				t.Fatal("permission bypass", role, w.Code, calls)
			}
			continue
		}
		if w.Code != 200 || calls != before+1 {
			t.Fatal(w.Code, w.Body.String(), calls)
		}
		wrongIdentity = true
		if w = request("GET", path, "", cookie); w.Code != 409 {
			t.Fatal("foreign executor result accepted", w.Code)
		}
		before = calls
		if w = request("GET", "/api/schedules/runs/"+ID()+"/log-cleanup", "", cookie); w.Code != 404 || calls != before {
			t.Fatal("nonexistent run forwarded", w.Code, calls)
		}
	}
}

func TestLogCleanupContinuationHTTPRequiresAdminOwnershipAndTerminalRun(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"admin", "viewer", "operator"} {
		accessUser(t, s, role, role, nil)
	}
	accessUser(t, s, "no-menu", "admin", []string{"sites"})
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	wrong := false
	in := LogCleanupContinueRequest{RequestID: run.ID, SiteID: schedule.TargetID, PlanSHA256: Hash("plan"), AcknowledgeUnknown: true}
	body, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/sites/"+schedule.TargetID+"/logs/operations/"+run.ID+"/continue" {
			t.Fatal("unsafe executor path", r.Method, r.URL.Path)
		}
		var got LogCleanupContinueRequest
		if e := json.NewDecoder(r.Body).Decode(&got); e != nil || got != in {
			t.Fatal("unbound continuation body", got, e)
		}
		out := LogCleanupContinuation{RequestID: run.ID, SiteID: schedule.TargetID, PlanSHA256: in.PlanSHA256, VerifiedAt: "2026-10-08T12:00:00Z", EvidenceSHA256: Hash("evidence")}
		if wrong {
			out.SiteID = ID()
		}
		encoded, e := json.Marshal(out)
		if e != nil {
			t.Fatal(e)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded))), Request: r}, nil
	})}}
	csrf := ""
	request := func(path, payload string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	path := "/api/schedules/runs/" + run.ID + "/log-cleanup/continue"
	if w := request(path, string(body), nil); w.Code != 401 || calls != 0 {
		t.Fatal("anonymous recovery", w.Code, calls)
	}
	for _, role := range []string{"viewer", "operator", "no-menu", "admin"} {
		login := request("/api/login", `{"username":"`+role+`","password":"access-test-password-long"}`, nil)
		if login.Code != 200 {
			t.Fatal(role, login.Code)
		}
		cookie := login.Result().Cookies()[0]
		var session struct {
			CSRF string `json:"csrf"`
		}
		if e := json.Unmarshal(login.Body.Bytes(), &session); e != nil || session.CSRF == "" {
			t.Fatal("missing login CSRF", e)
		}
		csrf = session.CSRF
		w := request(path, string(body), cookie)
		if role != "admin" {
			if w.Code != 403 || calls != 0 {
				t.Fatal("recovery permission bypass", role, w.Code, calls)
			}
			continue
		}
		if w.Code != 409 || calls != 0 {
			t.Fatal("running task forwarded", w.Code, calls)
		}
		if _, e = s.DB.Exec(`UPDATE schedule_runs SET state='failed' WHERE id=?`, run.ID); e != nil {
			t.Fatal(e)
		}
		if w = request(path, string(body), cookie); w.Code != 200 || calls != 1 {
			t.Fatal("terminal task recovery failed", w.Code, w.Body.String(), calls)
		}
		wrong = true
		if w = request(path, string(body), cookie); w.Code != 409 || calls != 2 {
			t.Fatal("foreign recovery result accepted", w.Code, calls)
		}
		if w = request("/api/schedules/runs/"+ID()+"/log-cleanup/continue", string(body), cookie); w.Code != 404 || calls != 2 {
			t.Fatal("foreign run forwarded", w.Code, calls)
		}
	}
}
