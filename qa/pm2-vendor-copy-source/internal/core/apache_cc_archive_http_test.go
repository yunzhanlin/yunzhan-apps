package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApacheCCArchiveHTTPOriginalIdentityAuthorizationAndAudit(t *testing.T) {
	s := testStore(t)
	adminUser := accessUser(t, s, "cc-archive-admin", "", nil)
	viewer := accessUser(t, s, "cc-archive-viewer", "viewer", []string{"software"})
	operator := accessUser(t, s, "cc-archive-operator", "operator", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	lastMethod, lastPath, lastBody := "", "", ""
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		lastMethod, lastPath = r.Method, r.URL.RequestURI()
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			lastBody = string(b)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"inode":"18446744073709551610","read_only":true}`))}, nil
	})}}
	request := func(method, path, body, csrf, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", a.Config.Origin, nil)
		var reply accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0], reply.CSRF
	}
	id := strings.Repeat("a", 32)
	base := "/api/software/apache-waf/cc-log/"
	body := `{"request_id":"` + id + `","expected_revision":7,"allow_incomplete":false}`
	retention := `{"sha256":"` + strings.Repeat("c", 64) + `","confirm_unknown":true}`
	history := `{"sha256":"` + strings.Repeat("d", 64) + `","confirm_preserve":true}`
	operations := []struct{ method, suffix, body string }{{"GET", "archives", ""}, {"GET", "archives/" + id, ""}, {"GET", "archives/" + id + "/chunks/31", ""}, {"GET", "requests/" + id, ""}, {"POST", "archive", body}, {"POST", "requests/" + id + "/close", body}, {"GET", "archives/" + id + "/recovery", ""}, {"POST", "archives/" + id + "/retain", retention}, {"GET", "archives/" + id + "/history", ""}, {"POST", "archives/" + id + "/history", history}}
	for _, name := range []string{viewer.Username, operator.Username} {
		cookie, csrf := login(name)
		for _, op := range operations {
			before := calls
			w := request(op.method, base+op.suffix, op.body, csrf, a.Config.Origin, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("nonadmin forwarded a private archive request", w.Code)
			}
		}
	}
	admin, csrf := login(adminUser.Username)
	for _, op := range operations {
		before := calls
		w := request(op.method, base+op.suffix, op.body, csrf, a.Config.Origin, admin)
		if w.Code != 200 || calls != before+1 || lastMethod != op.method || lastPath != "/v1/software/apache-waf/cc-log/"+op.suffix || !strings.Contains(w.Body.String(), "18446744073709551610") {
			t.Fatal("closed forwarding or exact integer changed", w.Code, lastPath, w.Body.String())
		}
		if op.method == "POST" && (op.suffix == "archive" || strings.HasSuffix(op.suffix, "/close")) {
			var got ApacheCCArchiveRequest
			if json.Unmarshal([]byte(lastBody), &got) != nil || got.RequestID != id || got.ExpectedRevision != 7 || got.AllowIncomplete {
				t.Fatal("original scalars changed", lastBody)
			}
		}
	}
	for _, operation := range operations {
		if operation.method != "POST" {
			continue
		}
		op := operation.suffix
		for _, auth := range []struct {
			cookie       *http.Cookie
			csrf, origin string
		}{{nil, csrf, a.Config.Origin}, {admin, "wrong", a.Config.Origin}, {admin, csrf, "https://foreign.invalid"}} {
			before := calls
			w := request("POST", base+op, operation.body, auth.csrf, auth.origin, auth.cookie)
			if w.Code < 400 || calls != before {
				t.Fatal("unsafe session reached Root", w.Code)
			}
		}
	}
	for _, v := range []struct{ method, suffix, body string }{
		{"GET", "archives?path=/etc/shadow", ""}, {"GET", "archives/not-hex", ""}, {"GET", "archives/" + id + "/chunks/128", ""}, {"GET", "archives/" + id + "/chunks/01", ""},
		{"POST", "archive", strings.Replace(body, `false`, `null`, 1)}, {"POST", "archive", strings.Replace(body, `"expected_revision":7`, `"expected_revision":7,"expected_revision":8`, 1)},
		{"POST", "requests/" + strings.Repeat("b", 32) + "/close", body},
		{"POST", "archives/" + id + "/retain", history}, {"POST", "archives/" + id + "/history", retention}, {"POST", "archives/" + id + "/retain", strings.Replace(retention, "true", "false", 1)}, {"POST", "archives/" + id + "/history", strings.Replace(history, "true", "null", 1)},
	} {
		before := calls
		w := request(v.method, base+v.suffix, v.body, csrf, a.Config.Origin, admin)
		if w.Code < 400 || calls != before {
			t.Fatal("unsafe original request forwarded", v, w.Code)
		}
	}
	for _, op := range operations {
		if op.method == "POST" && (strings.HasSuffix(op.suffix, "/retain") || strings.HasSuffix(op.suffix, "/history")) {
			if lastBody == "" {
				t.Fatal("missing forwarded digest request")
			}
			w := request(op.method, base+op.suffix, op.body, csrf, a.Config.Origin, admin)
			if w.Code != 200 || strings.TrimSpace(lastBody) != op.body {
				t.Fatal("exact digest/confirmation changed", lastBody, w.Code)
			}
		}
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_cc_archive_audit BEFORE INSERT ON audit_logs WHEN NEW.action='apache.cc-log.close-unstarted.requested' BEGIN SELECT RAISE(ABORT,'owned audit refusal'); END`); err != nil {
		t.Fatal(err)
	}
	before := calls
	w := request("POST", base+"requests/"+id+"/close", body, csrf, a.Config.Origin, admin)
	if w.Code != 503 || calls != before {
		t.Fatal("unaudited closure reached Root", w.Code)
	}
}
