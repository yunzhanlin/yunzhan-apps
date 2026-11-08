package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestApacheBodyReportBoundedFiltersPaginationAndHonestCounting(t *testing.T) {
	now := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	event := ApacheBodyEvent{Time: now.Add(-time.Hour).Format(time.RFC3339Nano), Engine: "2.9.15-yz5", SiteID: strings.Repeat("a", 32), RuleID: 941100, Phase: 2, Severity: 2, Mode: "block", Intercepted: true}
	other := event
	other.SiteID = strings.Repeat("b", 32)
	other.RuleID, other.Phase = 942100, 1
	snapshot := ApacheBodyEventsPage{Events: []ApacheBodyEvent{event, event, other}, Available: true, Partial: true, Rejected: 1, LogBytes: 512, MaxBytes: 32 << 20, BestEffort: true}
	out, err := BuildApacheBodyReport(snapshot, url.Values{"site_id": {event.SiteID}, "rule": {"941100"}, "phase": {"2"}, "limit": {"1"}, "page": {"2"}}, now)
	if err != nil || out.Matches != 2 || out.Scanned != 3 || len(out.Events) != 1 || len(out.Rules) != 1 || out.Rules[0].Count != 2 || !out.Partial || out.Rejected != 1 || out.Counting != ApacheBodyCountingContract || out.Scope == "" {
		t.Fatal(out, err)
	}
	if data, err := json.Marshal(out); err != nil || strings.Contains(string(data), `"blocked"`) || strings.Contains(string(data), `"request"`) || strings.Contains(string(data), `"ip"`) {
		t.Fatal("report claimed HTTP block/request identity", string(data), err)
	}
	for _, query := range []url.Values{{"path": {"/etc/shadow"}}, {"site_id": {"a.localhost"}}, {"phase": {"9"}}, {"rule": {"1", "2"}}, {"limit": {"1001"}}, {"page": {"0"}}, {"from": {"2026-01-01T00:00:00Z"}, "to": {now.Format(time.RFC3339)}}} {
		if _, err := BuildApacheBodyReport(snapshot, query, now); err == nil {
			t.Fatal("invalid report query accepted", query)
		}
	}
}

func TestApacheBodyReportHTTPAdminClosedReadAndUnverifiedResponse(t *testing.T) {
	s := testStore(t)
	for _, user := range []struct {
		name, role string
		menus      []string
	}{{"admin", "admin", nil}, {"viewer", "viewer", nil}, {"limited", "admin", []string{"runtimes"}}} {
		accessUser(t, s, user.name, user.role, user.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls, malformed := 0, false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/software/apache-waf/body-report" || r.URL.Query().Get("path") != "" {
			t.Fatal("report performed an unrelated operation", r.Method, r.URL.Path)
		}
		out, err := BuildApacheBodyReport(ApacheBodyEventsPage{Events: []ApacheBodyEvent{}, BestEffort: true, MaxBytes: 32 << 20}, r.URL.Query(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if malformed {
			out.Counting = "http_requests"
		}
		data, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}}
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	const path = "/api/software/apache-waf/body-report"
	if w := request("GET", path, "", nil); w.Code != 401 || calls != 0 {
		t.Fatal("anonymous numeric report access", w.Code, calls)
	}
	for _, name := range []string{"viewer", "limited", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, nil)
		if login.Code != 200 {
			t.Fatal("private fixture login failed", login.Code)
		}
		cookie := login.Result().Cookies()[0]
		before := calls
		if name != "admin" {
			if w := request("GET", path, "", cookie); w.Code != 403 || calls != before {
				t.Fatal("non-admin or missing menu gained numeric log access", name, w.Code, calls)
			}
			continue
		}
		for _, query := range []string{"?path=/etc/shadow", "?rule=1&rule=2", "?limit=1001", "?rule=100000000", "?page=01", "?site_domain=private.invalid"} {
			if w := request("GET", path+query, "", cookie); w.Code != 400 || calls != before {
				t.Fatal("unsafe numeric report request reached executor", query, w.Code, calls)
			}
		}
		if w := request("GET", path+"?limit=50", "", cookie); w.Code != 200 || calls != before+1 {
			t.Fatal("closed admin report rejected", w.Code, w.Body.String())
		}
		malformed = true
		if w := request("GET", path+"?limit=50", "", cookie); w.Code != 503 || strings.Contains(w.Body.String(), `"rule_matches":0`) {
			t.Fatal("unverified executor statistics appeared as a complete zero report", w.Code, w.Body.String())
		}
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("readonly report created a runtime operation", count, err)
	}
}
