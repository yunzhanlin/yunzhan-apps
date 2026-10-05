package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func analyticsFixture(t *testing.T, enabled bool) (*Server, Site, AnalyticsConfig) {
	t.Helper()
	s := testStore(t)
	if _, err := s.CreateSiteAtDomain("Analytics", "analytics-test", "analytics.example", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := s.Sites()
	if err != nil || len(sites) != 1 {
		t.Fatal(sites, err)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: sites[0].ID, Enabled: enabled, Clicks: true, Retention: 30})
	if err != nil {
		t.Fatal(err)
	}
	return a, sites[0], c
}

func analyticsRequest(a *Server, c AnalyticsConfig, v AnalyticsEvent, origin string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(v)
	r := httptest.NewRequest("POST", "/collect/analytics/event?site="+c.SiteID+"&key="+c.Key, strings.NewReader(string(body)))
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/123.0")
	r.RemoteAddr = "192.0.2.8:1234"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestAnalyticsDefaultsRevisionAndOrigin(t *testing.T) {
	a, site, c := analyticsFixture(t, false)
	initial, err := a.Store.analyticsConfig(ID())
	if err != nil || initial.Enabled || initial.Clicks || initial.Key != "" || initial.Revision != 0 || initial.Retention != 30 {
		t.Fatal(initial, err)
	}
	if _, err = a.Store.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: site.ID, Enabled: true, Retention: 30}); err == nil {
		t.Fatal("stale revision accepted")
	}
	c.Enabled = true
	saved, err := a.Store.saveAnalyticsConfig(context.Background(), c)
	if err != nil || saved.Revision != 2 || saved.Key != c.Key {
		t.Fatal(saved, err)
	}
	for _, days := range []int{0, 91, -1} {
		saved.Retention = days
		if _, err := a.Store.saveAnalyticsConfig(context.Background(), saved); err == nil {
			t.Fatal("unsafe retention", days)
		}
	}
	site.Settings.Domains = []string{"alias.example"}
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{"https://analytics.example", true}, {"http://ANALYTICS.example:8080", true}, {"https://alias.example", true},
		{"", false}, {"null", false}, {"https://analytics.example.evil", false}, {"https://analytics.example@evil.example", false},
		{"https://evil.example@analytics.example", false}, {"https://analytics.example/path", false}, {"https://analytics.example?token=x", false},
	} {
		if got := analyticsOrigin(site, tc.origin); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestAnalyticsPublicEndpointValidationAndPrivacy(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/watch?token=must-not-retain#secret", Referer: "https://search.example/query?secret=hidden", Browser: "Forged", Received: 1}
	for _, origin := range []string{"", "null", "https://attacker.example"} {
		if w := analyticsRequest(a, c, v, origin); w.Code != 403 {
			t.Fatal("untrusted origin", origin, w.Code, w.Body.String())
		}
	}
	badKey := c
	badKey.Key = ID()
	if w := analyticsRequest(a, badKey, v, "https://analytics.example"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, change := range []func(*AnalyticsEvent){
		func(e *AnalyticsEvent) { e.ID = "bad" }, func(e *AnalyticsEvent) { e.PageID = "bad" }, func(e *AnalyticsEvent) { e.Path = "//evil.example" },
		func(e *AnalyticsEvent) { e.Duration = -1 }, func(e *AnalyticsEvent) { e.X = 101 }, func(e *AnalyticsEvent) { e.Title = strings.Repeat("a", 257) },
		func(e *AnalyticsEvent) { e.Kind = "execute" }, func(e *AnalyticsEvent) { e.Referer = "file:///etc/passwd" },
	} {
		bad := v
		change(&bad)
		if w := analyticsRequest(a, c, bad, "https://analytics.example"); w.Code != 400 {
			t.Fatal("accepted invalid event", bad, w.Code)
		}
	}
	for _, body := range []string{`{"command":"id"}`, strings.Repeat("x", 4097), `{} {}`} {
		r := httptest.NewRequest("POST", "/collect/analytics/event?site="+c.SiteID+"&key="+c.Key, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://analytics.example")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for i := 0; i < 2; i++ {
		if w := analyticsRequest(a, c, v, "https://analytics.example"); w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var count int
	var raw, visitor, ip string
	if err := a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := a.Store.DB.QueryRow(`SELECT data,visitor,ip_hash FROM analytics_events`).Scan(&raw, &visitor, &ip); err != nil {
		t.Fatal(err)
	}
	if visitor == v.Visitor || len(visitor) != 64 || len(ip) != 64 || strings.Contains(raw, "must-not-retain") || strings.Contains(raw, "hidden") || strings.Contains(raw, "192.0.2.8") || strings.Contains(raw, "Forged") {
		t.Fatal("privacy or server authority violated", raw)
	}
	var stored AnalyticsEvent
	_ = json.Unmarshal([]byte(raw), &stored)
	if stored.Path != "/watch" || stored.Referer != "search.example" || stored.Received == 1 || stored.Browser != "Chrome" {
		t.Fatal(stored)
	}
	for header, value := range map[string]string{"DNT": "1", "Sec-GPC": "1", "User-Agent": "ExampleBot/1.0"} {
		body, _ := json.Marshal(v)
		r := httptest.NewRequest("POST", "/collect/analytics/event?site="+c.SiteID+"&key="+c.Key, strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://analytics.example")
		r.Header.Set(header, value)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&count)
	if count != 1 {
		t.Fatal("privacy opt-out or bot inserted data", count)
	}
}

func TestAnalyticsReportsCountNavigationsNotLifecycleBeacons(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	visitor, session, page := ID(), ID(), ID()
	events := []AnalyticsEvent{
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "pageview", Path: "/first"},
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "engagement", Path: "/first", Duration: 15},
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "performance", Path: "/first", TTFB: 50, FCP: 100, LCP: 200, CLSAvailable: true, CLS: .2},
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "performance", Path: "/first", TTFB: 50, FCP: 100, LCP: 300, CLSAvailable: true, CLS: 0},
		{ID: ID(), PageID: ID(), Visitor: visitor, Session: session, Kind: "pageview", Path: "/second"},
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "click", Path: "/first", X: 12, Y: 24},
		{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/first"},
	}
	for _, v := range events {
		if w := analyticsRequest(a, c, v, "https://analytics.example"); w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	out, err := a.Store.analyticsReport(context.Background(), c.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o := out["overview"].(map[string]any)
	for key, want := range map[string]int{"pv": 3, "uv": 2, "sessions": 2, "unique_network_peers": 1, "clicks": 1, "active_visitors": 2} {
		if o[key] != want {
			t.Fatal(key, o)
		}
	}
	if o["bounce_rate"] != float64(50) || o["avg_engagement_seconds"] != float64(7.5) {
		t.Fatal(o)
	}
	perf := out["performance"].(map[string]any)
	if p := perf["lcp"].(map[string]any); p["samples"] != 1 || p["p75"] != float64(300) {
		t.Fatal(p)
	}
	if p := perf["cls"].(map[string]any); p["samples"] != 1 || p["p75"] != float64(0) {
		t.Fatal("zero CLS must be a valid sample", p)
	}
	rows := out["sessions"].([]*analyticsSession)
	for _, ss := range rows {
		if ss.Pages == 2 && (ss.Entry != "/first" || ss.Exit != "/second" || len(ss.Journey) != 2) {
			t.Fatal(ss)
		}
	}
	for _, span := range [][2]string{{"bad", ""}, {"2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"}, {"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"}} {
		if _, err := a.Store.analyticsReport(context.Background(), c.SiteID, span[0], span[1], time.Now()); err == nil {
			t.Fatal("unbounded report", span)
		}
	}
}

func TestAnalyticsRetentionBudgetAndDisabledTracker(t *testing.T) {
	a, _, c := analyticsFixture(t, false)
	r := httptest.NewRequest("GET", "/collect/analytics/tracker.js?site="+c.SiteID+"&key="+c.Key, nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	c.Enabled = true
	c, _ = a.Store.saveAnalyticsConfig(context.Background(), c)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "pageshow") || w.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
		t.Fatal(w.Code)
	}
	v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/", Received: time.Now().Add(-40 * 24 * time.Hour).Unix()}
	if err := a.Store.storeAnalyticsEvent(context.Background(), c.SiteID, 30, v); err != nil {
		t.Fatal(err)
	}
	v.ID = ID()
	v.Received = time.Now().Unix()
	if err := a.Store.storeAnalyticsEvent(context.Background(), c.SiteID, 30, v); err != nil {
		t.Fatal(err)
	}
	var total int
	_ = a.Store.DB.QueryRow(`SELECT events FROM analytics_budget`).Scan(&total)
	if total != 1 {
		t.Fatal("retention or trigger count failed", total)
	}
	_, _ = a.Store.DB.Exec(`UPDATE analytics_budget SET events=?`, analyticsCapacity)
	v.ID = ID()
	if err := a.Store.storeAnalyticsEvent(context.Background(), c.SiteID, 30, v); err == nil {
		t.Fatal("capacity exceeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Store.storeAnalyticsEvent(ctx, c.SiteID, 30, v); err == nil {
		t.Fatal("canceled write succeeded")
	}
}

func TestAnalyticsRateLimitsAreBoundedAndReset(t *testing.T) {
	a := &Server{}
	now := time.Unix(120, 0)
	for i := 0; i < 100; i++ {
		if !a.analyticsAllowed("192.0.2.1", now) {
			t.Fatal(i)
		}
	}
	if a.analyticsAllowed("192.0.2.2", now) {
		t.Fatal("global per-second limit not enforced")
	}
	if !a.analyticsAllowed("192.0.2.1", now.Add(time.Second)) {
		t.Fatal("second limit did not reset")
	}
	a.analyticsGlobal = analyticsRate{}
	a.analyticsRates = map[string]analyticsRate{Hash("192.0.2.1"): {Window: now.Unix() / 60, Count: 1200}}
	if a.analyticsAllowed("192.0.2.1", now) {
		t.Fatal("peer limit not enforced")
	}
	if !a.analyticsAllowed("192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("peer minute limit did not reset")
	}
}

func TestAnalyticsAdminEndpointsStillRequireAuthCSRFAndInstalledModule(t *testing.T) {
	a, _, c := analyticsFixture(t, false)
	h, _ := bcrypt.GenerateFromPassword([]byte("analytics-test-password"), bcrypt.MinCost)
	_, err := a.Store.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", h, Now())
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	executor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/app-modules/website-analytics" {
			t.Errorf("unexpected executor request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]bool{"installed": installed}})
	}))
	defer executor.Close()
	address := strings.TrimPrefix(executor.URL, "http://")
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}}}
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
	path := "/api/analytics/sites/" + c.SiteID + "/config"
	if w := request("GET", path, "", "", "", nil); w.Code != 401 {
		t.Fatal("anonymous admin data", w.Code)
	}
	w := request("POST", "/api/login", `{"username":"admin","password":"analytics-test-password"}`, "", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var login map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	cookie := w.Result().Cookies()[0]
	body, _ := json.Marshal(c)
	for _, tc := range []struct {
		token, origin string
		want          int
	}{{"", "", 403}, {login["csrf"], "https://analytics.example", 403}, {login["csrf"], a.Config.Origin, 409}} {
		if w := request("POST", path, string(body), tc.token, tc.origin, cookie); w.Code != tc.want {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
	installed = true
	if w := request("POST", path, string(body), login["csrf"], a.Config.Origin, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	viewerID := ID()
	_, _ = a.Store.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, viewerID, "viewer", h, Now())
	_, _ = a.Store.DB.Exec(`INSERT INTO app_user_roles VALUES(?,?,?)`, viewerID, "viewer", "[]")
	if a.appRoleAllowed(identity{ID: viewerID}, httptest.NewRequest("GET", path, nil)) {
		t.Fatal("unscoped viewer accepted")
	}
}

func TestAnalyticsReportByteBudgetAndMaintenanceWithoutVisitors(t *testing.T) {
	a, _, c := analyticsFixture(t, false)
	v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/" + strings.Repeat("p", 1800), Received: time.Now().Unix()}
	raw, _ := json.Marshal(v)
	tx, err := a.Store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < analyticsReportBytes/len(raw)+100; i++ {
		if _, err = stmt.Exec(c.SiteID, ID(), v.Received, v.Visitor, v.Session, v.Kind, v.Path, "peer", string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	_ = stmt.Close()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	out, err := a.Store.analyticsReport(context.Background(), c.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out["partial"] != true || out["sampled_events"].(int) >= analyticsReportLimit {
		t.Fatal("byte budget not enforced", out["sampled_events"])
	}
	v.ID = ID()
	v.Received = time.Now().Add(-40 * 24 * time.Hour).Unix()
	if err = a.Store.storeAnalyticsEvent(context.Background(), c.SiteID, 30, v); err != nil {
		t.Fatal(err)
	}
	if err = a.Store.cleanupAnalytics(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var old int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE received<?`, time.Now().Add(-30*24*time.Hour).Unix()).Scan(&old)
	if old != 0 {
		t.Fatal("disabled site kept expired data", old)
	}
}

func TestAnalyticsSuccessfulUninstallStopsCollectionWithoutDeletingReports(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/"}
	if w := analyticsRequest(a, c, v, "https://analytics.example"); w.Code != 204 {
		t.Fatal(w.Code)
	}
	_, err := a.Store.QueueSoftwareAction("website-analytics", "uninstall", nil, ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	j, err := a.Store.NextRuntimeJob()
	if err != nil {
		t.Fatal(err)
	}
	// Store lifecycle only: no real software is uninstalled by this test.
	if err = a.Store.FinishRuntime(j, "", nil); err != nil {
		t.Fatal(err)
	}
	config, err := a.Store.analyticsConfig(c.SiteID)
	if err != nil || config.Enabled || config.Revision != c.Revision+1 {
		t.Fatal(config, err)
	}
	var count int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&count)
	if count != 1 {
		t.Fatal("uninstall deleted report", count)
	}
	if w := analyticsRequest(a, c, v, "https://analytics.example"); w.Code != 404 {
		t.Fatal("uninstalled collection still accepted", w.Code)
	}
}
