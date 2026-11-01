package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApacheNumericLogHTTPAuthorizationClosedForwardingAndAudit(t *testing.T) {
	s := testStore(t)
	adminUser := accessUser(t, s, "apache-numeric-log-admin", "", nil)
	viewer := accessUser(t, s, "apache-numeric-log-viewer", "viewer", []string{"software"})
	operator := accessUser(t, s, "apache-numeric-log-operator", "operator", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var gotMethod, gotPath, gotBody string
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"archives":[],"inode":18446744073709551610,"read_only":true}`))}, nil
	})}}
	request := func(method, path, body, token, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", token)
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
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var out accountSession
		if json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("login response")
		}
		return w.Result().Cookies()[0], out.CSRF
	}
	admin, csrf := login(adminUser.Username)
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	base := "/api/software/apache-waf/body-log/"
	remove := `{"sha256":"` + sha + `","confirm_delete":true}`
	for _, name := range []string{viewer.Username, operator.Username} {
		cookie, token := login(name)
		for _, v := range []struct{ method, path, body string }{{"GET", base + "archives", ""}, {"POST", base + "rotate", "{}"}, {"POST", base + "archives/" + id + "/remove", remove}} {
			before := calls
			w := request(v.method, v.path, v.body, token, a.Config.Origin, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("nonadmin reached maintenance", w.Code, w.Body.String())
			}
		}
	}
	for _, v := range []struct {
		cookie        *http.Cookie
		token, origin string
	}{{nil, csrf, a.Config.Origin}, {admin, "bad", a.Config.Origin}, {admin, csrf, "https://foreign.invalid"}} {
		before := calls
		w := request("POST", base+"rotate", "{}", v.token, v.origin, v.cookie)
		if w.Code < 400 || calls != before {
			t.Fatal("unsafe session reached executor", w.Code)
		}
	}
	before := calls
	out := request("GET", base+"archives", "", csrf, a.Config.Origin, admin)
	if out.Code != 200 || calls != before+1 || gotMethod != "GET" || gotPath != "/v1/software/apache-waf/body-log/archives" || !strings.Contains(out.Body.String(), "18446744073709551610") {
		t.Fatal("read or integer evidence forwarding", out.Code, gotPath, out.Body.String())
	}
	for _, v := range []struct{ path, body string }{{"rotate", "{}"}, {"archives/" + id + "/remove", remove}, {"archives/" + id + "/retain", `{"index_sha256":"` + sha + `","snapshot_sha256":"","snapshot_missing":true,"confirm_unknown":true}`}, {"index-stages/" + id + "/retain", `{"sha256":"` + sha + `","confirm_unknown":true}`}} {
		before := calls
		out = request("POST", base+v.path, v.body, csrf, a.Config.Origin, admin)
		if out.Code != 200 || calls != before+1 || gotMethod != "POST" || gotPath != "/v1/software/apache-waf/body-log/"+v.path {
			t.Fatal("closed maintenance forwarding", out.Code, gotPath, out.Body.String())
		}
		var want, got map[string]any
		json.Unmarshal([]byte(v.body), &want)
		json.Unmarshal([]byte(gotBody), &got)
		if len(want) != len(got) {
			t.Fatal("fields changed", gotBody)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatal("confirmation changed", k, gotBody)
			}
		}
	}
	for _, v := range []struct{ path, body string }{{"rotate?path=/etc/shadow", "{}"}, {"rotate", `{"confirm_delete":true}`}, {"archives/not-hex/remove", remove}, {"archives/" + id + "/remove", `{"sha256":"` + sha + `","confirm_delete":false,"confirm_delete":true}`}, {"archives/" + id + "/remove", `{"sha256":"` + sha + `","confirm_delete":null}`}} {
		before := calls
		out = request("POST", base+v.path, v.body, csrf, a.Config.Origin, admin)
		if out.Code < 400 || calls != before {
			t.Fatal("malformed request forwarded", v.path, out.Code)
		}
	}
	var audits int
	if err := s.DB.QueryRow("SELECT count(*)FROM audit_logs WHERE action LIKE 'apache.body-log.%'").Scan(&audits); err != nil || audits != 8 {
		t.Fatal("maintenance receipts not audited", audits, err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER block_apache_log_request_audit BEFORE INSERT ON audit_logs WHEN NEW.action='apache.body-log.rotate.requested' BEGIN SELECT RAISE(ABORT,'owned test failure'); END`); err != nil {
		t.Fatal(err)
	}
	before = calls
	out = request("POST", base+"rotate", "{}", csrf, a.Config.Origin, admin)
	if out.Code != 503 || calls != before {
		t.Fatal("unaudited operation dispatched", out.Code)
	}
}
