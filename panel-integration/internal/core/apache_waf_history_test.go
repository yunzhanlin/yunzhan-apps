package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApacheWAFHistoryClosedQueryBodyAndVersions(t *testing.T) {
	for _, q := range []string{"", "limit=1&offset=0", "limit=32&offset=612"} {
		if _, err := ApacheWAFHistoryQuery(q); err != nil {
			t.Fatal(q, err)
		}
	}
	for _, q := range []string{"limit=0", "limit=33", "offset=613", "offset=-1", "limit=01", "limit=1&limit=1", "off%73et=1&offset=1", "limit=1&port=0", "offset=%zz", "limit=1;offset=0", "offset=1.0", strings.Repeat("a", 257)} {
		if _, err := ApacheWAFHistoryQuery(q); err == nil {
			t.Fatal("unsafe query accepted", q)
		}
	}
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	valid := `{"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE APACHE TRANSACTION ` + id + `"}`
	if _, err := DecodeApacheWAFHistoryArchive([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"null", "[]", "{}", valid + " {}", valid[:len(valid)-1] + `,"limit":0}`, valid[:len(valid)-1] + `,"resource_id":"` + id + `"}`, valid[:len(valid)-1] + `,"resource_\u0069d":"` + id + `"}`, strings.Replace(valid, "expected_sha", "Expected_SHA", 1), strings.Replace(valid, sha, strings.ToUpper(sha), 1), strings.Replace(valid, `"resource_id":"`+id+`"`, `"resource_id":null`, 1), strings.Replace(valid, "ARCHIVE APACHE TRANSACTION", "ARCHIVE LOAD TRANSACTION", 1), strings.Repeat(" ", 4097)} {
		if _, err := DecodeApacheWAFHistoryArchive([]byte(raw)); err == nil {
			t.Fatal("unsafe archive accepted", raw)
		}
	}
	for _, v := range []string{"2.0.0", "2.1.0", "2.2.0", "2.3.0"} {
		if !ApacheWAFHistoryVersion(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"", "1.0", "2.3.1", "2.4.0", "v2.3.0", "2.3.0 ", "2.3.0-beta"} {
		if ApacheWAFHistoryVersion(v) {
			t.Fatal("future version accepted", v)
		}
	}
}

// Independent authenticated Core fixture; not a normal native Apache install.
func TestApacheWAFHistoryHTTPAuthorizationClosedForwardingAndAudit(t *testing.T) {
	s := testStore(t)
	adminUser := accessUser(t, s, "apache-history-admin", "", nil)
	viewer := accessUser(t, s, "apache-history-viewer", "viewer", []string{"software"})
	operator := accessUser(t, s, "apache-history-operator", "operator", nil)
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
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"apache_transactions":[],"configuration_changed":false}`))}, nil
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
	body := `{"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE APACHE TRANSACTION ` + id + `"}`
	base := "/api/software/apache-waf/"
	for _, name := range []string{viewer.Username, operator.Username} {
		cookie, token := login(name)
		for _, v := range []struct{ method, path, body string }{{"GET", base + "transactions?limit=16&offset=0", ""}, {"POST", base + "archive-transaction", body}} {
			before := calls
			w := request(v.method, v.path, v.body, token, a.Config.Origin, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("non-admin reached executor", w.Code)
			}
		}
	}
	for _, v := range []struct {
		cookie        *http.Cookie
		token, origin string
	}{{nil, csrf, a.Config.Origin}, {admin, "wrong", a.Config.Origin}, {admin, csrf, "https://foreign.invalid"}} {
		before := calls
		w := request("POST", base+"archive-transaction", body, v.token, v.origin, v.cookie)
		if w.Code < 400 || calls != before {
			t.Fatal("unsafe authorization reached executor", w.Code)
		}
	}
	before := calls
	w := request("GET", base+"transactions?limit=32&offset=16", "", csrf, a.Config.Origin, admin)
	if w.Code != 200 || calls != before+1 || gotMethod != "GET" || gotPath != "/v1/software/apache-waf/transactions?limit=32&offset=16" || w.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatal("read forwarding", w.Code, gotPath, w.Body.String())
	}
	before = calls
	w = request("POST", base+"archive-transaction", body, csrf, a.Config.Origin, admin)
	if w.Code != 200 || calls != before+1 || gotMethod != "POST" || gotPath != "/v1/software/apache-waf/archive-transaction" {
		t.Fatal("archive forwarding", w.Code, w.Body.String())
	}
	var want, got map[string]string
	json.Unmarshal([]byte(body), &want)
	json.Unmarshal([]byte(gotBody), &got)
	if len(got) != 3 {
		t.Fatal("generic fields leaked", gotBody)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatal("original selection changed", gotBody)
		}
	}
	for _, v := range []struct{ method, path, body string }{{"GET", base + "transactions?limit=16&limit=16", ""}, {"GET", base + "transactions?limit=16&path=/etc/passwd", ""}, {"POST", base + "archive-transaction?unknown=1", body}, {"POST", base + "archive-transaction", body[:len(body)-1] + `,"limit":0}`}, {"POST", base + "archive-transaction", strings.Repeat(" ", 4097)}} {
		before := calls
		w := request(v.method, v.path, v.body, csrf, a.Config.Origin, admin)
		if w.Code != 400 || calls != before {
			t.Fatal("invalid input reached executor", w.Code, w.Body.String())
		}
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action LIKE 'apache-waf.transaction.archive-%'`).Scan(&count); err != nil || count != 2 {
		t.Fatal("archive audit pair", count, err)
	}
}
