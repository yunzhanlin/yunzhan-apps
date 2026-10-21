package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real session, ACL, HTTP, audit and SQLite paths; executor responses are
// deliberate fixtures, not proof of a native/signed application installation.
func TestStatisticsGeoHTTPAuthorityAndReplayBeforeExecutor(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "geo-admin", "admin", nil)
	accessUser(t, s, "geo-viewer", "viewer", nil)
	accessUser(t, s, "geo-operator", "operator", nil)
	accessUser(t, s, "geo-restricted-admin", "admin", []string{"overview"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	executorCalls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		executorCalls++
		if r.Method != "GET" || r.URL.Path != "/v1/statistics/geodata" {
			t.Fatal("unauthorized geographic mutation reached executor", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"installed":false,"app_version":"","stored":[]}`))}, nil
	})}}
	request := func(method, path, raw, csrf, origin, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", a.Config.Origin, "", nil)
		var auth accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(w.Result().Cookies()) != 1 {
			t.Fatal("actual isolated login failed", w.Code)
		}
		return w.Result().Cookies()[0], auth.CSRF
	}
	endpoint := "/api/software/website-statistics-v2/geodata"
	in := statisticsGeoSelectionFixture()
	raw, _ := json.Marshal(in)
	for _, name := range []string{"geo-viewer", "geo-operator", "geo-restricted-admin"} {
		cookie, csrf := login(name)
		for _, method := range []string{"GET", "POST"} {
			if w := request(method, endpoint, string(raw), csrf, a.Config.Origin, "denied", cookie); w.Code != 403 || executorCalls != 0 {
				t.Fatal("role/menu denial reached geographic executor", name, method, w.Code, executorCalls)
			}
		}
	}
	cookie, csrf := login(admin.Username)
	for _, denied := range []struct {
		token, origin string
		cookie        *http.Cookie
	}{{"wrong", a.Config.Origin, cookie}, {csrf, "https://foreign.invalid", cookie}, {csrf, a.Config.Origin, nil}} {
		if w := request("POST", endpoint, string(raw), denied.token, denied.origin, "denied", denied.cookie); w.Code < 400 || executorCalls != 0 {
			t.Fatal("session/CSRF/origin denial reached geographic executor", w.Code, executorCalls)
		}
	}
	for _, invalid := range []string{`{}`, `{"action":null}`, string(raw) + `{}`, strings.Repeat(" ", 1025)} {
		if w := request("POST", endpoint, invalid, csrf, a.Config.Origin, "invalid", cookie); w.Code != 400 || executorCalls != 0 {
			t.Fatal("malformed selection reached executor", w.Code, executorCalls)
		}
	}
	if w := request("POST", endpoint, string(raw), csrf, a.Config.Origin, "absent", cookie); w.Code != 409 || executorCalls != 1 {
		t.Fatal("uninstalled application accepted geographic job", w.Code, executorCalls)
	}
	if w := request("GET", endpoint, "", csrf, a.Config.Origin, "", cookie); w.Code != 200 || executorCalls != 2 {
		t.Fatal("uninstalled status was not inspectable", w.Code, executorCalls)
	}
	id, err := s.QueueStatisticsGeo(in, "original-request", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w := request("POST", endpoint, string(raw), csrf, a.Config.Origin, "original-request", cookie)
		var out struct {
			JobID    string `json:"job_id"`
			Replayed bool   `json:"replayed"`
		}
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.JobID != id || !out.Replayed || executorCalls != 2 {
			t.Fatal("lost HTTP reply redispatched original job", w.Code, out, executorCalls)
		}
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM runtime_jobs WHERE kind='statistics_geodata'").Scan(&count); err != nil || count != 1 {
		t.Fatal("denied/replayed HTTP created new jobs", count, err)
	}
}
