package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
)

func analyticsReplayTestReceipt(t *testing.T, s *Store) {
	t.Helper()
	_, err := s.DB.Exec("INSERT INTO app_registry_receipts(app_id,scope,target,version,sha256,updated_at) VALUES('website-analytics','website-analytics','website-analytics',?,?,?)",
		appcatalog.AnalyticsSessionActivityVersion, strings.Repeat("a", 64), Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestAnalyticsReplayHTTPConsentScopeAndRetention(t *testing.T) {
	a, site, config := analyticsFixture(t, true)
	if _, err := a.Store.CreateSiteAtDomain("Replay other", "replay-other", "other.example", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := a.Store.Sites()
	if err != nil || len(sites) != 2 {
		t.Fatal(sites, err)
	}
	otherID := sites[0].ID
	if otherID == site.ID {
		otherID = sites[1].ID
	}
	otherConfig, err := a.Store.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: otherID, Enabled: true, Retention: 1})
	if err != nil {
		t.Fatal(err)
	}
	admin := accessUser(t, a.Store, "replay-admin", "admin", nil)
	viewer := accessUser(t, a.Store, "replay-viewer", "viewer", []string{"sites"})
	if _, err := a.Store.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id=?", "[\""+site.ID+"\"]", viewer.ID); err != nil {
		t.Fatal(err)
	}

	type auth struct {
		cookie *http.Cookie
		csrf   string
	}
	call := func(method, path string, body any, credentials auth) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, &buf)
		if credentials.cookie != nil {
			req.AddCookie(credentials.cookie)
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", credentials.csrf)
			req.Header.Set("Origin", a.Config.Origin)
		}
		res := httptest.NewRecorder()
		a.ServeHTTP(res, req)
		return res
	}
	expect := func(res *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
		t.Helper()
		if res.Code != status {
			t.Fatalf("got %d, want %d: %s", res.Code, status, res.Body.String())
		}
		return res
	}
	login := func(username string) auth {
		res := expect(call("POST", "/api/login", map[string]string{"username": username, "password": "access-test-password-long"}, auth{}), 200)
		var session accountSession
		if err := json.Unmarshal(res.Body.Bytes(), &session); err != nil || session.CSRF == "" || len(res.Result().Cookies()) != 1 {
			t.Fatal("login response invalid", err)
		}
		return auth{res.Result().Cookies()[0], session.CSRF}
	}
	adminAuth, viewerAuth := login(admin.Username), login(viewer.Username)
	policyPath := "/api/analytics/sites/" + site.ID + "/replay-policy"
	policy := analyticsReplayPolicy{SiteID: site.ID, Enabled: true, Sample: 1}
	expect(call("GET", policyPath, nil, auth{}), 401)
	expect(call("GET", policyPath, nil, viewerAuth), 403)
	expect(call("POST", policyPath, policy, auth{cookie: adminAuth.cookie}), 403)
	baseline := expect(call("GET", policyPath, nil, adminAuth), 200)
	var defaults analyticsReplayPolicy
	if err := json.Unmarshal(baseline.Body.Bytes(), &defaults); err != nil || defaults.Enabled || defaults.Sample != 10 || defaults.Revision != 0 {
		t.Fatal("invalid disabled defaults", baseline.Body.String(), err)
	}
	expect(call("POST", policyPath, policy, adminAuth), 409)
	analyticsReplayTestReceipt(t, a.Store)

	tracker := "/collect/analytics/tracker.js?site=" + site.ID + "&key=" + config.Key
	if res := expect(call("GET", tracker, nil, auth{}), 200); strings.Contains(res.Body.String(), "yunzhan:analytics-replay-consent") {
		t.Fatal("opt-in tracker served before activation")
	}
	wrongSite := policy
	wrongSite.SiteID = otherID
	expect(call("POST", policyPath, wrongSite, adminAuth), 400)
	expect(call("POST", policyPath, policy, adminAuth), 200)
	expect(call("POST", policyPath, policy, adminAuth), 409)
	if res := expect(call("GET", tracker, nil, auth{}), 200); !strings.Contains(res.Body.String(), "yunzhan:analytics-replay-consent") {
		t.Fatal("activated tracker missing consent integration")
	}
	otherPath := "/api/analytics/sites/" + otherID + "/replay-policy"
	expect(call("POST", otherPath, analyticsReplayPolicy{SiteID: otherID, Enabled: true, Sample: 100}, adminAuth), 200)

	const origin = "https://analytics.example"
	base := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: strings.Repeat("0", 8) + ID()[8:], Kind: "pageview", Path: "/catalog?token=concealed", Title: "private-title"}
	frame := base
	frame.ID, frame.Kind, frame.Path = ID(), "replay", "/forged-replay-path"
	frame.Replay = &analyticsReplayFrame{Width: 800, Height: 600, Scroll: 120, Pointer: []int{1000, 0, 1}, Tiles: [][]int{{0, 0, 1000, 1000, 0xffffff, 0}, {11, 28, 375, 55, 0x12abef, 3}}}
	expect(analyticsRequest(a, config, frame, origin), 409)
	expect(analyticsRequest(a, config, base, origin), 204)
	expect(analyticsRequest(a, config, frame, "https://other.example"), 403)
	outsideSample := frame
	outsideSample.Session = strings.Repeat("f", 32)
	expect(analyticsRequest(a, config, outsideSample, origin), 403)
	bad := frame
	bad.Replay = &analyticsReplayFrame{Width: 800, Height: 600, Tiles: [][]int{{999, 0, 2, 1000, 0xffffff, 0}}}
	expect(analyticsRequest(a, config, bad, origin), 400)
	bad = frame
	bad.Kind = "pageview"
	expect(analyticsRequest(a, config, bad, origin), 400)
	expect(analyticsRequest(a, otherConfig, frame, "https://other.example"), 409)
	expect(analyticsRequest(a, config, frame, origin), 204)
	expect(analyticsRequest(a, config, frame, origin), 204)

	var visitor, session string
	if err := a.Store.DB.QueryRow("SELECT visitor,session FROM analytics_events WHERE site_id=? AND kind='pageview'", site.ID).Scan(&visitor, &session); err != nil {
		t.Fatal(err)
	}
	if visitor == base.Visitor || session == base.Session {
		t.Fatal("raw browser ID retained")
	}
	now := time.Now().UTC()
	query := url.Values{"visitor": {visitor}, "from": {now.Add(-time.Minute).Format(time.RFC3339)}, "to": {now.Add(time.Minute).Format(time.RFC3339)}}
	replayPath := "/api/analytics/sites/" + site.ID + "/sessions/" + session + "/replay?" + query.Encode()
	expect(call("GET", replayPath, nil, auth{}), 401)
	expect(call("GET", replayPath, nil, viewerAuth), 403)
	expect(call("GET", replayPath+"&visitor="+visitor, nil, adminAuth), 400)
	res := expect(call("GET", replayPath, nil, adminAuth), 200)
	var received struct {
		Frames []analyticsReplayDisplayFrame
	}
	if err := json.Unmarshal(res.Body.Bytes(), &received); err != nil || res.Header().Get("Cache-Control") != "private, no-store" ||
		len(received.Frames) != 1 || received.Frames[0].Path != "/catalog" ||
		!received.Frames[0].Viewport.valid() || received.Frames[0].Viewport.Pointer[2] != 1 {
		t.Fatal("invalid replay", res.Body.String(), err)
	}
	for _, secret := range []string{"concealed", "forged-replay-path", "private-title", base.Visitor, base.Session, base.PageID} {
		if strings.Contains(res.Body.String(), secret) {
			t.Fatal("retained an untrusted or private field")
		}
	}
	for _, isolated := range []string{
		strings.Replace(replayPath, site.ID, otherID, 1),
		strings.Replace(replayPath, visitor, ID()+ID(), 1),
	} {
		if res := expect(call("GET", isolated, nil, adminAuth), 200); !strings.Contains(res.Body.String(), "\"frames\":[]") {
			t.Fatal("isolated replay disclosed", res.Body.String())
		}
	}
	policy.Revision, policy.Enabled = 1, false
	expect(call("POST", policyPath, policy, adminAuth), 200)
	frame.ID = ID()
	expect(analyticsRequest(a, config, frame, origin), 403)
	expect(call("GET", replayPath, nil, adminAuth), 200)

	beforeExpiry := now.Add(-8 * 24 * time.Hour)
	if _, err := a.Store.DB.Exec("UPDATE analytics_replay_frames SET received_ms=? WHERE site_id=?", beforeExpiry.UnixMilli(), site.ID); err != nil {
		t.Fatal(err)
	}
	query.Set("from", now.Add(-9*24*time.Hour).Format(time.RFC3339))
	res = expect(call("GET", strings.Split(replayPath, "?")[0]+"?"+query.Encode(), nil, adminAuth), 200)
	if !strings.Contains(res.Body.String(), "\"frames\":[]") {
		t.Fatal("expired frame exposed before cleanup")
	}
	if err := a.Store.cleanupAnalytics(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var frames, events int
	if err := a.Store.DB.QueryRow("SELECT (SELECT count(*) FROM analytics_replay_frames),(SELECT count(*) FROM analytics_events)").Scan(&frames, &events); err != nil || frames != 0 || events != 1 {
		t.Fatal("replay expiry changed normal statistics", frames, events, err)
	}
}
