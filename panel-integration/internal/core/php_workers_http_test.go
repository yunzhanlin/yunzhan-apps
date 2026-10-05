package core

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPHPWorkerHTTPUsesSiteScopeCSRFAndServerIdentity(t *testing.T) {
	s := testStore(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	for _, role := range []string{"admin", "viewer", "operator"} {
		if _, e := s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, role, role, hash, Now()); e != nil {
			t.Fatal(e)
		}
	}
	job, e := s.CreateSite("PHP workers", "php-workers", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(`UPDATE sites SET status='running',php_version_id='php-8.4.25' WHERE id=?`, siteID)
	if e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"viewer", "operator"} {
		if _, e = s.DB.Exec(`INSERT INTO app_user_roles VALUES(?,?,?)`, role, role, `["`+siteID+`"]`); e != nil {
			t.Fatal(e)
		}
	}
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method == "POST" {
			var in PHPWorker
			if e := json.NewDecoder(r.Body).Decode(&in); e != nil || in.SiteID != siteID || !ValidID(in.ID) || in.ObservedReleaseID != "php-8.4.25" {
				t.Fatalf("untrusted worker identity: %+v %v", in, e)
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"workers":[]}`))}, nil
	})}}
	request := func(method, path, body, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		r.Header.Set("X-CSRF-Token", token)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	base := "/api/sites/" + siteID + "/php-workers"
	if w := request("GET", base, "", "", nil); w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, role := range []string{"viewer", "operator", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+role+`","password":"test-password-long"}`, "", nil)
		if login.Code != 200 {
			t.Fatal(login.Body.String())
		}
		var auth map[string]string
		_ = json.Unmarshal(login.Body.Bytes(), &auth)
		cookie := login.Result().Cookies()[0]
		if w := request("GET", base, "", auth["csrf"], cookie); w.Code != 200 {
			t.Fatal(role, w.Code, w.Body.String())
		}
		before := calls
		if role != "admin" {
			if w := request("GET", "/api/sites/"+ID()+"/php-workers", "", auth["csrf"], cookie); w.Code != 403 || calls != before {
				t.Fatal("cross-site read", role, w.Code)
			}
		}
		body := `{"name":"queue","entry":"artisan","arguments":["queue:work"],"restart_policy":"always","memory_mb":256,"tasks_max":64,"stop_seconds":30}`
		if w := request("POST", base, body, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("missing CSRF", role, w.Code)
		}
		w := request("POST", base, body, auth["csrf"], cookie)
		want := 201
		if role == "viewer" {
			want = 403
		}
		if w.Code != want {
			t.Fatal(role, w.Code, w.Body.String())
		}
		if role != "viewer" {
			before = calls
			malicious := strings.TrimSuffix(body, "}") + `,"release_id":"php-8.2.33","command":"sh"}`
			if w = request("POST", base, malicious, auth["csrf"], cookie); w.Code != 400 || calls != before {
				t.Fatal("caller selected runtime/command", w.Code)
			}
		}
	}
}
