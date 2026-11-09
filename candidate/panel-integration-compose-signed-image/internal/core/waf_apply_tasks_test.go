package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func wafTaskTestServer(t *testing.T) (*Store, *Server, func(string) *http.Cookie) {
	t.Helper()
	s := testStore(t)
	for _, u := range []struct {
		name, role string
		menus      []string
	}{
		{"waf-admin", "admin", []string{"runtimes", "security"}},
		{"audit-admin", "admin", []string{"audit"}},
		{"runtime-admin", "admin", []string{"runtimes"}},
		{"reader", "viewer", []string{"overview"}},
		{"operator", "operator", []string{"files"}},
	} {
		accessUser(t, s, u.name, u.role, u.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("read-only WAF task API called executor: %s", r.URL)
		return nil, nil
	})}}
	login := func(name string) *http.Cookie {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"username": name, "password": "access-test-password-long"})
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 || len(w.Result().Cookies()) != 1 {
			t.Fatal("actual login", w.Code)
		}
		return w.Result().Cookies()[0]
	}
	return s, a, login
}

func wafTaskTestRead(a *Server, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestWAFApplyTaskReadUsesExistingMenusNotGlobalAudit(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	id, err := s.QueueSoftwareAction("nginx-waf", "configure", WAFSettings(DefaultWAFConfig()), "original-waf-task", "waf-admin")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/software/nginx-waf/jobs/" + id
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal("anonymous task read", w.Code)
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(name)); w.Code != 403 {
			t.Fatal("broadened authorization", name, w.Code)
		}
	}
	cookie := login("waf-admin")
	if w := wafTaskTestRead(a, "/api/jobs/"+id, cookie); w.Code != 403 {
		t.Fatal("global audit grant broadened", w.Code)
	}
	w := wafTaskTestRead(a, path, cookie)
	var got map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("actual scoped read", w.Code)
	}
	want := map[string]any{"id": id, "target_id": "nginx-waf", "kind": "software_configure", "state": "queued", "error": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("closed task receipt", got)
	}
	for _, private := range []string{"payload", "steps", "settings", "site_id", "created_at", "idempotency_key"} {
		if strings.Contains(w.Body.String(), `"`+private+`"`) {
			t.Fatal("private or unrelated field leaked", private)
		}
	}
}

func TestWAFApplyTaskReadOnlyBoundIdentityAndTerminalStates(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	for _, app := range []string{"nginx-waf", "apache-waf"} {
		var settings map[string]any
		if app == "nginx-waf" {
			settings = WAFSettings(DefaultWAFConfig())
		} else {
			settings = WAFSettings(DefaultApacheWAFConfig())
		}
		for _, action := range []string{"install", "configure"} {
			id, err := s.QueueSoftwareAction(app, action, settings, app+action, "waf-admin")
			if err != nil {
				t.Fatal(err)
			}
			for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention", "cancelled"} {
				detail := ""
				if state == "failed" || state == "needs_attention" {
					detail = "actual uncertain or refused executor result"
				}
				if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state=?,error=? WHERE id=?`, state, detail, id); err != nil {
					t.Fatal(err)
				}
				w := wafTaskTestRead(a, "/api/software/"+app+"/jobs/"+id, cookie)
				var got wafApplyTaskStatus
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ID != id || got.TargetID != app || got.Kind != "software_"+action || got.State != state || got.Error != detail {
					t.Fatal("exact task state", app, action, state, w.Code)
				}
			}
			if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state='failed' WHERE id=?`, id); err != nil {
				t.Fatal(err)
			}
			other := "nginx-waf"
			if app == other {
				other = "apache-waf"
			}
			if w := wafTaskTestRead(a, "/api/software/"+other+"/jobs/"+id, cookie); w.Code != 404 {
				t.Fatal("wrong app task leaked", w.Code)
			}
		}
	}
}

func TestWAFApplyTaskReadRejectsUnknownStateKindQueryAndNeverMutates(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	id, err := s.QueueSoftwareAction("nginx-waf", "configure", WAFSettings(DefaultWAFConfig()), "original-readonly", "waf-admin")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/software/nginx-waf/jobs/" + id
	for _, test := range []struct {
		path   string
		status int
	}{
		{path + "?page=1", 400}, {path + "?state=succeeded&state=failed", 400}, {path + "?", 400},
		{"/api/software/nginx-waf/jobs/NOT-AN-ID", 400},
		{"/api/software/nginx-waf/jobs/" + ID(), 404},
	} {
		if w := wafTaskTestRead(a, test.path, cookie); w.Code != test.status {
			t.Fatal("unreviewed input", test.path, w.Code)
		}
	}
	for _, change := range []struct {
		state, kind, detail string
		status              int
	}{
		{"ready", "software_configure", "", 409}, {"succeeded", "software_update", "", 404},
		{"succeeded", "waf_engine_build", "", 404}, {"failed", "software_configure", strings.Repeat("x", 32769), 409},
	} {
		if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state=?,kind=?,error=? WHERE id=?`, change.state, change.kind, change.detail, id); err != nil {
			t.Fatal(err)
		}
		if w := wafTaskTestRead(a, path, cookie); w.Code != change.status {
			t.Fatal("unknown task outcome accepted", change.state, change.kind, w.Code)
		}
	}
	if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state='running',kind='software_configure',error='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	before, err := s.Job(id)
	if err != nil {
		t.Fatal(err)
	}
	var auditBefore int
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if w := wafTaskTestRead(a, path, cookie); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	after, err := s.Job(id)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read changed task", err)
	}
	var auditAfter int
	if err = s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&auditAfter); err != nil || auditBefore != auditAfter {
		t.Fatal("read created audit mutation", err)
	}
	if _, err = s.DB.Exec(`DROP TABLE runtime_jobs`); err != nil {
		t.Fatal(err)
	}
	w := wafTaskTestRead(a, path, cookie)
	data, _ := io.ReadAll(w.Result().Body)
	if w.Code != 503 || strings.Contains(string(data), "SQL") || strings.Contains(string(data), "runtime_jobs") {
		t.Fatal("database failure leaked internal detail", w.Code, string(data))
	}
}
