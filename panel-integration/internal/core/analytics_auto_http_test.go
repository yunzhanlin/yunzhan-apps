package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Exercises the real authenticated HTTP/queue/SQLite/commit paths. The
// executor transport is deliberately a fixture, not native Nginx evidence.
func TestAnalyticsAutoHTTPQueuesWithoutPrematurePublicOptInAndAllowsSafeOptOut(t *testing.T) {
	a, site, initial := analyticsFixture(t, false)
	created, err := a.Store.NextJob()
	if err != nil || created.Kind != "create_site" || a.Store.Finish(created, "running", "", nil) != nil {
		t.Fatal("private initial site fixture", err)
	}
	a.Config.Listen = "127.0.0.1:19220"
	accessUser(t, a.Store, "admin", "admin", nil)
	version, calls, broken := "2.3.0", 0, false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		status, body := 200, ""
		switch r.URL.Path {
		case "/v1/app-modules/website-analytics":
			body = `{"status":{"installed":true,"version":"` + version + `"}}`
		case "/v1/sites/preview":
			var candidate Site
			if json.NewDecoder(r.Body).Decode(&candidate) != nil || candidate.ID != site.ID {
				t.Fatal("wrong preview site")
			}
			if r.URL.Query().Get("analytics_baseline") != "1" {
				if candidate.Settings.AnalyticsInjectHTML && candidate.Settings.AnalyticsEndpoint != a.Config.Listen {
					t.Fatal("browser-supplied upstream or wrong opt-in")
				}
				if !candidate.Settings.AnalyticsInjectHTML && candidate.Settings.AnalyticsEndpoint != "" {
					t.Fatal("opt-out retained an upstream")
				}
				if broken && candidate.Settings.AnalyticsInjectHTML {
					status, body = 409, `{"error":"private fixture: actual engine readiness unavailable"}`
				}
			}
			if body == "" {
				body = `{"current":"private baseline","candidate":"private baseline","config_sha":"` + Hash("private baseline") + `"}`
			}
		default:
			t.Fatal("unexpected executor request", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(method, path, body, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/login", `{"username":"admin","password":"access-test-password-long"}`, "", "", nil)
	var auth accountSession
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || len(login.Result().Cookies()) != 1 {
		t.Fatal("actual private login failed", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	path := "/api/analytics/sites/" + site.ID + "/config"
	public := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/collect/analytics/auto.js?site="+site.ID, nil)
		r.Host = site.Domain
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	read := func(enabled bool, revision int64) AnalyticsConfig {
		t.Helper()
		w := request("GET", path, "", auth.CSRF, "", cookie)
		var cfg AnalyticsConfig
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cfg) != nil || cfg.AutoInjectHTML == nil || *cfg.AutoInjectHTML != enabled || cfg.Enabled != enabled || cfg.Revision != revision {
			t.Fatal("applied config GET violated commit boundary", w.Code, cfg)
		}
		return cfg
	}
	body := `{"enabled":true,"clicks":true,"retention_days":30,"revision":1,"auto_inject_html":true,"proxy_endpoint":"attacker.example:80"}`
	if w := request("POST", path, strings.Replace(body, `"retention_days":`, `"retention":`, 1), auth.CSRF, "unknown-field", cookie); w.Code != 400 || calls != 0 {
		t.Fatal("unknown configuration field reached executor", w.Code, calls)
	}
	if w := request("POST", path, body, "", "opt-in", cookie); w.Code != 403 || calls != 0 {
		t.Fatal("CSRF reached the privileged executor", w.Code, calls)
	}
	queued := request("POST", path, body, auth.CSRF, "opt-in", cookie)
	var job map[string]string
	if queued.Code != 202 || json.Unmarshal(queued.Body.Bytes(), &job) != nil || !ValidID(job["job_id"]) || calls != 3 {
		t.Fatal("actual configuration not queued", queued.Code, queued.Body.String(), calls)
	}
	read(false, initial.Revision)
	if public().Code != 404 {
		t.Fatal("queued candidate prematurely exposed the public write key")
	}
	before := calls
	if w := request("POST", path, body, auth.CSRF, "opt-in", cookie); w.Code != 202 || calls != before || !strings.Contains(w.Body.String(), job["job_id"]) {
		t.Fatal("queued lost reply changed the task", w.Code, calls)
	}
	if w := request("POST", path, strings.Replace(body, `"auto_inject_html":true`, `"auto_inject_html":false`, 1), auth.CSRF, "opt-in", cookie); w.Code != 409 || calls != before {
		t.Fatal("changed intent reused a task", w.Code, calls)
	}
	pending, err := a.Store.NextJob()
	if err != nil || pending.ID != job["job_id"] {
		t.Fatal("wrong durable job", err)
	}
	var payload JobPayload
	if json.Unmarshal([]byte(pending.Payload), &payload) != nil || payload.Settings == nil || !payload.Settings.AnalyticsInjectHTML || payload.Settings.AnalyticsEndpoint != a.Config.Listen || payload.Analytics == nil || payload.Analytics.AutoInjectHTML == nil || !*payload.Analytics.AutoInjectHTML {
		t.Fatal("durable candidate does not bind the real site intent")
	}
	if err := a.Store.Finish(pending, "running", "private simulated apply failure", nil); err != nil {
		t.Fatal(err)
	}
	read(false, initial.Revision)
	if public().Code != 404 {
		t.Fatal("failed apply exposed the public write key")
	}
	if err := a.Store.Retry(pending.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	pending, err = a.Store.NextJob()
	if err != nil || a.Store.Finish(pending, "running", "", nil) != nil {
		t.Fatal("private commit fixture", err)
	}
	cfg := read(true, initial.Revision+1)
	if cfg.ProxyEndpoint != a.Config.Listen || cfg.Key != initial.Key || public().Code != 200 {
		t.Fatal("committed auto script or derived loopback endpoint unavailable")
	}
	if w := request("POST", path, body, auth.CSRF, "opt-in", cookie); w.Code != 202 || calls != before {
		t.Fatal("committed lost reply re-previewed or re-queued")
	}
	broken = true
	body2 := `{"enabled":true,"clicks":true,"retention_days":30,"revision":2,"auto_inject_html":true}`
	if w := request("POST", path, body2, auth.CSRF, "broken-engine", cookie); w.Code != 409 {
		t.Fatal("unready preview queued an enable", w.Code)
	}
	version = "2.2.0"
	before = calls
	if w := request("POST", path, body2, auth.CSRF, "old-version", cookie); w.Code != 409 || calls != before+1 {
		t.Fatal("old module reached an injection preview", w.Code, calls)
	}
	event := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/actual-core-http"}
	if w := analyticsRequest(a, cfg, event, "https://"+site.Domain); w.Code != 204 {
		t.Fatal("committed collector refused a real core event", w.Code)
	}
	optOut := `{"enabled":false,"clicks":true,"retention_days":30,"revision":2,"auto_inject_html":false}`
	w := request("POST", path, optOut, auth.CSRF, "opt-out", cookie)
	if w.Code != 202 || public().Code != 200 {
		t.Fatal("safe opt-out unavailable with old/unready engine or prematurely committed", w.Code)
	}
	pending, err = a.Store.NextJob()
	payload = JobPayload{}
	if err != nil || json.Unmarshal([]byte(pending.Payload), &payload) != nil || payload.Settings == nil || payload.Settings.AnalyticsInjectHTML || payload.Settings.AnalyticsEndpoint != "" || a.Store.Finish(pending, "running", "", nil) != nil {
		t.Fatal("safe opt-out was not atomically committed", err)
	}
	disabled := read(false, initial.Revision+2)
	var count int
	if public().Code != 404 || disabled.Key != initial.Key || a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE site_id=?`, site.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("opt-out left a live script or removed the collected history", count)
	}
	t.Log("PASS authenticated HTTP/queue/SQLite atomic commit, immutable lost-reply intent, no premature public key, safe opt-out despite old/unready engine; mock executor transport, NOT native Nginx acceptance")
}
