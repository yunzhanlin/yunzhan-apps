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

func TestStorageUsageHTTPAuthorizationReadOnlyAndOpaque(t *testing.T) {
	s := testStore(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	for _, role := range []string{"admin", "viewer"} {
		if _, err := s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, role, role, hash, Now()); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = s.DB.Exec(`INSERT INTO app_user_roles VALUES('viewer','viewer','[]')`)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if err != nil {
		t.Fatal(err)
	}
	reads, rootCode := 0, 200
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/storage/usage" {
			t.Fatal("observer performed unexpected root action", r.Method, r.URL.Path)
		}
		reads++
		body := `{"filesystem_path":"/srv/panel","disk_total":4096,"disk_used":2048,"disk_available":2048,"other_bytes":1024,"categories":[{"id":"websites","label":"网站文件","paths":["/srv/panel/sites"],"bytes":1024,"state":"complete"}],"complete":true,"reconciled":true,"sampled_at":"2026-10-12T00:00:00Z","private":"CORE-SECRET"}`
		if rootCode != 200 {
			body = `{"error":"PRIVATE-EXECUTOR-ERROR"}`
		}
		return &http.Response{StatusCode: rootCode, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/storage/usage", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(role string) *http.Cookie {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+role+`","password":"test-password-long"}`))
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0]
	}
	if w := request(nil); w.Code != 401 || reads != 0 {
		t.Fatal("anonymous recovery access", w.Code, reads)
	}
	if w := request(login("viewer")); w.Code != 403 || reads != 0 {
		t.Fatal("site viewer recovery access", w.Code, reads)
	}
	cookie := login("admin")
	w := request(cookie)
	if w.Code != 200 || reads != 1 || strings.Contains(w.Body.String(), "CORE-SECRET") {
		t.Fatal("private images exposed", w.Code, w.Body.String())
	}
	var page FileStorageUsage
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.OtherBytes == nil || *page.OtherBytes != 1024 || page.FilesystemPath != "/srv/panel" {
		t.Fatal(page, err)
	}
	r := httptest.NewRequest("GET", "/api/storage/usage?path=/etc", nil)
	r.AddCookie(cookie)
	q := httptest.NewRecorder()
	a.ServeHTTP(q, r)
	if q.Code != 400 || reads != 1 {
		t.Fatal("custom scope accepted", q.Code, reads)
	}
	rootCode = 503
	w = request(cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE-EXECUTOR-ERROR") {
		t.Fatal("private root error exposed", w.Code, w.Body.String())
	}
	var jobs int
	_ = s.DB.QueryRow("SELECT count(*) FROM runtime_jobs").Scan(&jobs)
	if jobs != 0 {
		t.Fatal("observer queued a mutation", jobs)
	}
}
