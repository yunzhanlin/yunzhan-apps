package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func funnelEvent(t *testing.T, s *Store, site, visitor, session, page, path string, received int64) {
	t.Helper()
	v := AnalyticsEvent{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "pageview", Path: path, Received: received}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?,?)`, site, v.ID, received, visitor, session, "pageview", path, "private-peer", string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyticsFunnelOrderRetryWindowDedupAndIsolation(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	now := time.Now()
	start := now.UTC().Truncate(24*time.Hour).Unix() + 1
	// Complete, with an unrelated page between stages and a duplicate beacon.
	v, sess, page := ID(), ID(), ID()
	funnelEvent(t, a.Store, c.SiteID, v, sess, page, "/entry", start)
	funnelEvent(t, a.Store, c.SiteID, v, sess, page, "/checkout", start+1)
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/unrelated", start+2)
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/checkout", start+3)
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/done", start+5)
	// A completed session cannot count a second conversion.
	for j, p := range []string{"/entry", "/checkout", "/done"} {
		funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), p, start+6+int64(j))
	}
	// Out-of-order page sequence only reaches the second stage.
	v, sess = ID(), ID()
	for j, p := range []string{"/done", "/checkout", "/entry", "/done", "/checkout"} {
		funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), p, start+int64(j))
	}
	// Timeout keeps the reached first stage but does not fabricate conversion.
	v, sess = ID(), ID()
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/entry", start)
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/checkout", start+61)
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/done", start+62)
	// Retry after timeout can complete, using its viable later entrance.
	v, sess = ID(), ID()
	for j, p := range []string{"/entry", "/checkout", "/entry", "/checkout", "/done"} {
		funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), p, start+int64(j)*61)
	}
	// The preceding retry times out too; a real bounded retry succeeds.
	for j, p := range []string{"/entry", "/checkout", "/done"} {
		funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), p, start+300+int64(j))
	}
	// Do not combine different visitors even if the session value collides.
	shared := ID()
	funnelEvent(t, a.Store, c.SiteID, ID(), shared, ID(), "/entry", start)
	funnelEvent(t, a.Store, c.SiteID, ID(), shared, ID(), "/checkout", start+1)
	funnelEvent(t, a.Store, c.SiteID, ID(), shared, ID(), "/done", start+2)
	if _, err := a.Store.CreateSiteAtDomain("Other analytics", "other-analytics", "other.example", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, _ := a.Store.Sites()
	other := ""
	for _, site := range sites {
		if site.ID != c.SiteID {
			other = site.ID
		}
	}
	v, sess = ID(), ID()
	for j, p := range []string{"/entry", "/checkout", "/done"} {
		funnelEvent(t, a.Store, other, v, sess, ID(), p, start+int64(j))
	}
	var before int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&before)
	out, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/entry", "/checkout", "/done"}, time.Unix(start, 0).Format(time.RFC3339), time.Unix(start+400, 0).Format(time.RFC3339), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Partial || out.CompletedSessions != 2 || out.Steps[0].Sessions != 5 || out.Steps[1].Sessions != 3 || out.Steps[2].Sessions != 2 {
		t.Fatal(out)
	}
	if out.Steps[0].DropOff != 2 || out.Steps[1].DropOff != 1 || out.Steps[2].OverallRate != 40 || out.Duration["average"] != 3.5 || out.Duration["p75"] != 5 {
		t.Fatal(out)
	}
	var after int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&after)
	encoded, _ := json.Marshal(out)
	if before != after || strings.Contains(string(encoded), "private-peer") || strings.Contains(string(encoded), shared) {
		t.Fatal("mutation or private output", string(encoded))
	}
}

func TestAnalyticsFunnelRepeatedStepsRequireDistinctPageviews(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	now := time.Now()
	start := now.UTC().Truncate(24*time.Hour).Unix() + 1
	v, sess, page := ID(), ID(), ID()
	funnelEvent(t, a.Store, c.SiteID, v, sess, page, "/same", start)
	funnelEvent(t, a.Store, c.SiteID, v, sess, page, "/same", start+1)
	out, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/same", "/same"}, "", "", 30, now)
	if err != nil || out.CompletedSessions != 0 || out.UniquePageviews != 1 {
		t.Fatal(out, err)
	}
	funnelEvent(t, a.Store, c.SiteID, v, sess, ID(), "/same", start+2)
	out, err = a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/same", "/same"}, "", "", 30, now)
	if err != nil || out.CompletedSessions != 1 || out.Duration["average"] != 2 {
		t.Fatal(out, err)
	}
}

func TestAnalyticsFunnelInputBoundsAndEmptyUnknownDuration(t *testing.T) {
	a, _, c := analyticsFixture(t, false)
	now := time.Now()
	for _, steps := range [][]string{nil, {"/"}, {"/", "//evil"}, {"/", "https://evil.example"}, {"/", "/a?token=private"}, {"/", "/a#secret"}, {"/", "/a\\b"}, {"/", "/a\n"}, {"/", "/%ZZ"}, {"/", strings.Repeat("p", 2049)}, {"/", "/", "/", "/", "/", "/", "/", "/", "/"}} {
		if _, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, steps, "", "", 30, now); err == nil {
			t.Fatal("accepted invalid paths", steps)
		}
	}
	for _, minutes := range []int{0, -1, 1441} {
		if _, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/", "/done"}, "", "", minutes, now); err == nil {
			t.Fatal("window", minutes)
		}
	}
	for _, span := range [][2]string{{"bad", ""}, {"2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"}, {"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"}} {
		if _, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/", "/done"}, span[0], span[1], 30, now); err == nil {
			t.Fatal("span", span)
		}
	}
	out, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{"/入口", "/done"}, "", "", 30, now)
	if err != nil || out.Steps[0].Path != "/%E5%85%A5%E5%8F%A3" || out.CompletedSessions != 0 || len(out.Duration) != 0 || out.Steps[1].OverallRate != 0 || out.Partial {
		t.Fatal(out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = a.Store.analyticsFunnelReport(ctx, c.SiteID, []string{"/", "/done"}, "", "", 30, now); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestAnalyticsFunnelHTTPAuthenticationAndMenuCeiling(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	users := []identity{accessUser(t, a.Store, "funnel-admin", "admin", nil), accessUser(t, a.Store, "funnel-limited", "admin", []string{"files"}), accessUser(t, a.Store, "funnel-viewer", "viewer", []string{"sites"}), accessUser(t, a.Store, "funnel-operator", "operator", []string{"sites"})}
	for _, u := range users[2:] {
		_, _ = a.Store.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+c.SiteID+`"]`, u.ID)
	}
	path := "/api/analytics/sites/" + c.SiteID + "/funnel?step=%2F&step=%2Fdone"
	request := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := request(path, nil); w.Code != 401 {
		t.Fatal("unauthenticated", w.Code)
	}
	for i, u := range users {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u.Username+`","password":"access-test-password-long"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		cookie := w.Result().Cookies()[0]
		w = request(path, cookie)
		want := 403
		if i == 0 {
			want = 200
		}
		if w.Code != want {
			t.Fatal(u.Username, w.Code, w.Body.String())
		}
		if i == 0 {
			if w.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("private analytics cache")
			}
			for _, suffix := range []string{"&window_minutes=0", "&window_minutes=1441", "&window_minutes=NaN", "&step=" + url.QueryEscape("/a?secret=x")} {
				if w = request(path+suffix, cookie); w.Code != 400 {
					t.Fatal(suffix, w.Code, w.Body.String())
				}
			}
			if w = request(strings.Replace(path, c.SiteID, ID(), 1), cookie); w.Code != 404 {
				t.Fatal("unknown site", w.Code)
			}
		}
	}
}

func TestAnalyticsFunnelEventAndByteBudgets(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "events", true: "bytes"}[large], func(t *testing.T) {
			a, _, c := analyticsFixture(t, false)
			now := time.Now()
			received := now.Unix()
			path := "/entry"
			count := analyticsReportLimit + 1
			if large {
				path = "/" + strings.Repeat("p", 1800)
				count = 5000
			}
			v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: path, Received: received}
			raw, _ := json.Marshal(v)
			tx, err := a.Store.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			stmt, err := tx.Prepare(`INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				t.Fatal(err)
			}
			for j := 0; j < count; j++ {
				if _, err = stmt.Exec(c.SiteID, ID(), received, v.Visitor, v.Session, "pageview", path, "peer", string(raw)); err != nil {
					t.Fatal(err)
				}
			}
			_ = stmt.Close()
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			out, err := a.Store.analyticsFunnelReport(context.Background(), c.SiteID, []string{path, "/done"}, "", "", 30, now)
			if err != nil || !out.Partial || out.SampledPageviews > analyticsReportLimit || large && out.SampledPageviews >= count {
				t.Fatal(out, err)
			}
		})
	}
}
