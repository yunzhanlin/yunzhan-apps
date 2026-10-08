package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAFBodyRetentionGovernanceAdminMenuCSRFAndClosedRequest(t *testing.T) {
	s := testStore(t)
	for _, v := range []struct {
		name, role string
		menus      []string
	}{{"admin", "admin", nil}, {"viewer", "viewer", nil}, {"limited", "admin", []string{"runtimes"}}} {
		accessUser(t, s, v.name, v.role, v.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/software/nginx-waf/body-log/retention"
	valid := `{"sha256":"` + strings.Repeat("a", 64) + `","acknowledge_unknown_deletion_not_repeated":true}`
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.RawQuery != "" || r.URL.Path != "/v1/software/nginx-waf/body-log/retention" && r.URL.Path != "/v1/software/nginx-waf/body-log/retention/retain" {
			t.Fatal("arbitrary privileged target", r.URL)
		}
		if r.Method == "POST" {
			data, _ := io.ReadAll(r.Body)
			if string(data) != valid {
				t.Fatal("unexpected privileged body", string(data))
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"available":false}`))}, nil
	})}}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", base, "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", base+"/retain", valid, "", nil); w.Code != 401 {
		t.Fatal(w.Code)
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
		if w := request("POST", base+"/retain", valid, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("CSRF bypass", w.Code)
		}
		if name != "admin" {
			if w := request("GET", base, "", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("menu/role read bypass", name, w.Code)
			}
			if w := request("POST", base+"/retain", valid, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("menu/role write bypass", name, w.Code)
			}
			continue
		}
		for _, body := range []string{`{}`, `null`, strings.Replace(valid, "true", "false", 1), strings.Replace(valid, "true", "null", 1), strings.Replace(valid, "sha256", "SHA256", 1), strings.TrimSuffix(valid, "}") + `,"sha256":"` + strings.Repeat("a", 64) + `"}`, strings.TrimSuffix(valid, "}") + `,"path":"/etc/shadow"}`, valid + ` {}`} {
			if w := request("POST", base+"/retain", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed request", body, w.Code)
			}
		}
		if w := request("GET", base+"?path=/private", "", auth.CSRF, cookie); w.Code != 400 || calls != before {
			t.Fatal(w.Code)
		}
		if w := request("POST", base+"/retain?force=true", valid, auth.CSRF, cookie); w.Code != 400 || calls != before {
			t.Fatal(w.Code)
		}
		if w := request("GET", base, "", auth.CSRF, cookie); w.Code != 200 || calls != before+1 {
			t.Fatal(w.Code)
		}
		if w := request("POST", base+"/retain", valid, auth.CSRF, cookie); w.Code != 200 || calls != before+2 {
			t.Fatal(w.Code, w.Body.String())
		}
		var audit int
		if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action IN ('waf.body-log.retention-review-requested','waf.body-log.retention-unknown-retained')`).Scan(&audit); err != nil || audit != 2 {
			t.Fatal("missing request/result audit", audit, err)
		}
		if _, err := s.DB.Exec(`CREATE TRIGGER refuse_retention_request_audit BEFORE INSERT ON audit_logs WHEN NEW.action='waf.body-log.retention-review-requested' BEGIN SELECT RAISE(ABORT,'owned audit failure'); END`); err != nil {
			t.Fatal(err)
		}
		if w := request("POST", base+"/retain", valid, auth.CSRF, cookie); w.Code != 500 || calls != before+2 {
			t.Fatal("audit failure still called executor", w.Code, calls)
		}
		if _, err := s.DB.Exec(`DROP TRIGGER refuse_retention_request_audit`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`CREATE TRIGGER refuse_retention_result_audit BEFORE INSERT ON audit_logs WHEN NEW.action='waf.body-log.retention-unknown-retained' BEGIN SELECT RAISE(ABORT,'owned result audit failure'); END`); err != nil {
			t.Fatal(err)
		}
		if w := request("POST", base+"/retain", valid, auth.CSRF, cookie); w.Code != 503 || calls != before+3 || !strings.Contains(w.Body.String(), "请刷新状态") {
			t.Fatal("result audit failure declared success or repeated executor", w.Code, calls, w.Body.String())
		}
		if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.body-log.retention-unknown-retained'`).Scan(&audit); err != nil || audit != 1 {
			t.Fatal("failed result audit fabricated success", audit, err)
		}
	}
}
