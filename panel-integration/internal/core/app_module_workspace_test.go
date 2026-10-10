package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModuleWorkspacesCoverActualOperations(t *testing.T) {
	for _, def := range AppModules() {
		sections := ModuleWorkspace(def.ID)
		if len(sections) == 0 {
			t.Fatal("missing workspace", def.ID)
		}
		fields, actions, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, field := range def.Fields {
			fields[field.Key] = true
		}
		for _, section := range sections {
			if ids[section.ID] || section.Help == "" || section.Label == "" {
				t.Fatal("invalid section", def.ID, section)
			}
			ids[section.ID] = true
			for _, field := range section.Fields {
				if !fields[field] {
					t.Fatal("unknown workspace field", def.ID, field)
				}
			}
			for _, action := range section.Actions {
				if !ValidAppModuleAction(def.ID, action) {
					t.Fatal("unknown workspace operation", def.ID, action)
				}
				actions[action] = true
			}
		}
		for _, action := range def.Actions {
			if action != "history" && !actions[action] {
				t.Fatal("hidden operation", def.ID, action)
			}
		}
	}
}

func TestModuleInstallationNeverPersistsBusinessCredentials(t *testing.T) {
	for _, value := range []map[string]any{{"password": "secret"}, {"token": "secret"}, {"remote_private_key": "secret"}, {"remote_target": map[string]any{"password": "secret"}}, {"environment_patch": map[string]any{"API_KEY": "secret"}}} {
		if _, err := validateModuleSettings(value); err == nil {
			t.Fatal("business credential accepted as plaintext installation settings")
		}
	}
	if _, err := validateModuleSettings(map[string]any{"site_id": "owned"}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSyncHTTPAuthorizationAndCSRFBeforeExecutor(t *testing.T) {
	s := testStore(t)
	master := accessUser(t, s, "remote-master", "", nil)
	viewer := accessUser(t, s, "remote-viewer", "viewer", []string{"files"})
	operator := accessUser(t, s, "remote-operator", "operator", nil)
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"status":{"installed":true}}`
		if r.Method == "POST" {
			body = `{"queued":true}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(route, body, token, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", token)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", a.Config.Origin, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v accountSession
		if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
			t.Fatal(e)
		}
		return w.Result().Cookies()[0], v.CSRF
	}
	adminCookie, adminToken := login(master.Username)
	for _, name := range []string{viewer.Username, operator.Username} {
		cookie, token := login(name)
		for _, action := range []string{"save-remote", "queue-remote", "cancel-remote", "recover-remote", "probe-remote", "remote-jobs", "remote-archive", "archive-remote-job", "remote-plans", "schedule-remote-plan", "pause-remote-plan", "resume-remote-plan", "remove-remote-plan"} {
			before := calls
			w := request("/api/app-modules/files-sync/"+action, "{}", token, a.Config.Origin, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("non-admin remote authority reached executor", action, w.Code, calls-before)
			}
		}
	}
	for _, identity := range []struct {
		token, origin string
		cookie        *http.Cookie
	}{{"wrong", a.Config.Origin, adminCookie}, {adminToken, "https://foreign.invalid", adminCookie}, {adminToken, a.Config.Origin, nil}} {
		for _, action := range []string{"queue-remote", "remote-plans", "schedule-remote-plan", "pause-remote-plan", "resume-remote-plan", "remove-remote-plan"} {
			before := calls
			w := request("/api/app-modules/files-sync/"+action, "{}", identity.token, identity.origin, identity.cookie)
			if w.Code < 400 || calls != before {
				t.Fatal("missing session/CSRF/origin reached executor", action, w.Code)
			}
		}
	}
	before := calls
	w := request("/api/app-modules/files-sync/queue-remote", "{}", adminToken, a.Config.Origin, adminCookie)
	if w.Code != 200 || calls != before+2 {
		t.Fatal("authorized bounded dispatcher did not forward fixed route", w.Code, calls-before)
	}
}

func TestModuleHistoryBoundedAndContainsNoSecrets(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 130; i++ {
		if err := s.recordAppModuleEvent("platform-ops", fmt.Sprint(i), "admin", errors.New("secret-token-in-error")); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.appModuleHistory("platform-ops")
	if err != nil {
		t.Fatal(err)
	}
	rows := result.(map[string]any)["history"].([]map[string]any)
	if len(rows) != 100 || rows[0]["action"] != "129" || rows[99]["action"] != "30" {
		t.Fatal(rows)
	}
	b, _ := json.Marshal(result)
	if strings.Contains(string(b), "secret-token") {
		t.Fatal("history leaked error contents")
	}
}

func TestDailyReportArchiveIsReadOnlyAndValidated(t *testing.T) {
	a := &Server{Store: testStore(t)}
	_, err := a.Store.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-05','{"sites":9}','2026-10-05T01:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.dailyReportOperation(context.Background(), "archive", AppModuleInput{})
	if err != nil || len(result.(map[string]any)["reports"].([]map[string]any)) != 1 {
		t.Fatal(result, err)
	}
	result, err = a.dailyReportOperation(context.Background(), "report", AppModuleInput{ResourceID: "2026-10-05"})
	if err != nil || result.(map[string]any)["sites"] != float64(9) {
		t.Fatal(result, err)
	}
	for _, day := range []string{"2026-02-30", "../2026-10-05", "2026-10-06"} {
		if _, err = a.dailyReportOperation(context.Background(), "report", AppModuleInput{ResourceID: day}); err == nil {
			t.Fatal("invalid or missing report accepted", day)
		}
	}
}
