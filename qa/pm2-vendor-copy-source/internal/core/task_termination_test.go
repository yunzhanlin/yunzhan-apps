package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func taskSignalCoreFixture(t *testing.T, reply string, executorErr error) (*Store, *Server, identity, *int) {
	t.Helper()
	s := testStore(t)
	u := accessUser(t, s, "task-audit-admin", "admin", []string{"system-tools"})
	calls := new(int)
	a := &Server{Store: s, Executor: &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		if r.Method != "POST" || r.URL.Path != "/v1/app-modules/task-manager/terminate" {
			t.Fatal("unrelated executor operation", r.Method, r.URL.Path)
		}
		var in AppModuleInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID != 42 || in.StartTime != 12345 {
			t.Fatal("original process replaced", in, err)
		}
		var requested int
		if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.requested' AND target='pid:42:start:12345'`).Scan(&requested); err != nil || requested < 1 {
			t.Fatal("RPC before durable requested audit", requested, err)
		}
		if executorErr != nil {
			return nil, executorErr
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(reply))}, nil
	})}}}
	return s, a, u, calls
}

const taskSignalFixtureReply = `{"pid":42,"signal":"SIGTERM","signal_accepted":true,"exit_verified":false}`

func TestTaskTerminationDurableRequestThenClosedSignalAuditNotExit(t *testing.T) {
	s, a, u, calls := taskSignalCoreFixture(t, taskSignalFixtureReply, nil)
	out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345})
	if err != nil || *calls != 1 || !taskSignalReplyMatches(out.(map[string]any), 42) {
		t.Fatal(out, err, *calls)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor=? AND target='pid:42:start:12345' AND (action='app-module.terminate.requested' OR action='app-module.terminate') AND result LIKE '%exit unverified'`, u.Username).Scan(&count); err != nil || count != 2 {
		t.Fatal("missing requested/result identity audits", count, err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_task_requested BEFORE INSERT ON audit_logs WHEN NEW.action='app-module.terminate.requested' BEGIN SELECT RAISE(ABORT,'requested audit fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345}); err == nil || out != nil || *calls != 1 {
		t.Fatal("failed requested audit dispatched", out, err, *calls)
	}
}

func TestTaskTerminationFailedResultAuditRemainsUnknownWithoutRetry(t *testing.T) {
	s, a, u, calls := taskSignalCoreFixture(t, taskSignalFixtureReply, nil)
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_task_result BEFORE INSERT ON audit_logs WHEN NEW.action='app-module.terminate' BEGIN SELECT RAISE(ABORT,'result audit fixture'); END`); err != nil {
		t.Fatal(err)
	}
	out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345})
	if err == nil || out != nil || *calls != 1 || !strings.Contains(err.Error(), "可能已发送") {
		t.Fatal("failed audit certified success or retried", out, err, *calls)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.requested'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("original request not retained", count, err)
	}
}

func TestTaskTerminationLostMalformedOrWrongOriginalReplyStaysUnknown(t *testing.T) {
	for _, reply := range []string{"", `not-json`, `{"pid":43,"signal":"SIGTERM","signal_accepted":true,"exit_verified":false}`, `{"pid":42,"signal":"SIGKILL","signal_accepted":true,"exit_verified":false}`, `{"pid":42,"signal":"SIGTERM","signal_accepted":true,"exit_verified":true}`, strings.TrimSuffix(taskSignalFixtureReply, "}") + `,"secret":"extra"}`} {
		s, a, u, calls := taskSignalCoreFixture(t, reply, nil)
		out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345})
		if err == nil || out != nil || *calls != 1 {
			t.Fatal("unknown signal certified or repeated", out, err, *calls)
		}
		var unknown int
		if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.unknown' AND target='pid:42:start:12345'`).Scan(&unknown); err != nil || unknown != 1 {
			t.Fatal("unknown original evidence absent", unknown, err)
		}
	}
	_, a, u, calls := taskSignalCoreFixture(t, "", errors.New("actual transport fixture lost reply"))
	if out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345}); err == nil || out != nil || *calls != 1 {
		t.Fatal("lost reply retried or green", out, err, *calls)
	}
}

func TestTaskTerminationInvalidRevokedAndCancelledRequestsNeverDispatch(t *testing.T) {
	s, a, u, calls := taskSignalCoreFixture(t, taskSignalFixtureReply, nil)
	for _, in := range []AppModuleInput{{PID: 1, StartTime: 1}, {PID: -1, StartTime: 1}, {PID: 42}, {PID: 2147483648, StartTime: 1}} {
		if out, err := a.terminateAppTask(context.Background(), u, in); err == nil || out != nil {
			t.Fatal("invalid process accepted", in, out, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := a.terminateAppTask(ctx, u, AppModuleInput{PID: 42, StartTime: 12345}); err == nil || out != nil {
		t.Fatal("cancelled request accepted", out, err)
	}
	if _, err := s.DB.Exec(`UPDATE app_user_menus SET menu_ids='[]' WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if out, err := a.terminateAppTask(context.Background(), u, AppModuleInput{PID: 42, StartTime: 12345}); err == nil || out != nil || *calls != 0 {
		t.Fatal("revoked operation dispatched", out, err, *calls)
	}
	var requested int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.requested'`).Scan(&requested); err != nil || requested != 0 {
		t.Fatal("invalid request recorded as accepted", requested, err)
	}
}

func TestTaskTerminationActualAuthenticatedHTTPUsesAuditedPath(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "task-http-admin", "admin", []string{"system-tools"})
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"status":{"id":"task-manager","installed":true}}`
		if r.Method == "POST" {
			calls++
			var count int
			if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.requested'`).Scan(&count); err != nil || count != 1 || r.URL.Path != "/v1/app-modules/task-manager/terminate" {
				t.Fatal("authenticated route bypassed audit", count, err, r.URL.Path)
			}
			body = taskSignalFixtureReply
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	cookie := login("task-http-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	r := httptest.NewRequest("POST", "/api/app-modules/task-manager/terminate", strings.NewReader(`{"pid":42,"start_time":12345}`))
	r.Header.Set("Origin", a.Config.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var out map[string]any
	if w.Code != 200 || calls != 1 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !taskSignalReplyMatches(out, 42) {
		t.Fatal("authenticated audited signal route", w.Code, calls)
	}
	denied := func(cookie *http.Cookie, token string) {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/app-modules/task-manager/terminate", strings.NewReader(`{"pid":42,"start_time":12345}`))
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", token)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 || calls != 1 {
			t.Fatal("missing current system-tools permission or valid CSRF dispatched a signal", w.Code, calls)
		}
	}
	denied(cookie, "wrong-fixture-csrf")
	runtimeCookie := login("runtime-admin")
	denied(runtimeCookie, wafBackupArchiveCoreCSRF(t, a, runtimeCookie))
	if _, err := s.DB.Exec(`UPDATE app_user_menus SET menu_ids='[]' WHERE user_id=(SELECT id FROM users WHERE username='task-http-admin')`); err != nil {
		t.Fatal(err)
	}
	denied(cookie, csrf)
	t.Log("Actual Core HTTP/login/CSRF/SQLite audit behavior with a closed executor response fixture; not native process signaling")
}
