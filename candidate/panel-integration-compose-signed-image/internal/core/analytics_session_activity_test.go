package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
)

func TestAnalyticsSessionActivityHTTPPrivacyScopeAndBounds(t *testing.T) {
	a, site, cfg := analyticsFixture(t, true)
	visitor, session := ID(), ID()
	for _, v := range []AnalyticsEvent{
		{Kind: "pageview", Path: "/cart?order=private-value", Title: "private-title", Referer: "https://private-source.example"},
		{Kind: "click", Path: "/cart", X: 0, Y: 62.5},
		{Kind: "engagement", Path: "/cart", Duration: 4.5},
	} {
		v.ID, v.PageID, v.Visitor, v.Session = ID(), ID(), visitor, session
		if w := analyticsRequest(a, cfg, v, "https://analytics.example"); w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	rawVisitor, rawSession := visitor, session
	if err := a.Store.DB.QueryRow("SELECT visitor,session FROM analytics_events WHERE site_id=? AND kind='pageview'", site.ID).Scan(&visitor, &session); err != nil {
		t.Fatal(err)
	}
	if visitor == rawVisitor || session == rawSession || !validAnalyticsActivityHash(visitor) || !validAnalyticsActivityHash(session) {
		t.Fatal("server identifiers were not scoped")
	}
	if _, err := a.Store.CreateSiteAtDomain("Other", "analytics-other", "other.example", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := a.Store.Sites()
	if err != nil || len(sites) != 2 {
		t.Fatal(sites, err)
	}
	other := sites[0]
	if other.ID == site.ID {
		other = sites[1]
	}
	funnelEvent(t, a.Store, other.ID, visitor, session, ID(), "/other-private", time.Now().Unix())
	funnelEvent(t, a.Store, site.ID, ID(), session, ID(), "/another-visitor", time.Now().Unix())
	admin := accessUser(t, a.Store, "activity-admin", "admin", nil)
	viewer := accessUser(t, a.Store, "activity-viewer", "viewer", []string{"sites"})
	if _, err := a.Store.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id=?", `["`+site.ID+`"]`, viewer.ID); err != nil {
		t.Fatal(err)
	}
	cookie := func(name string) *http.Cookie {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+name+`","password":"access-test-password-long"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0]
	}
	from, to := time.Now().UTC().Add(-time.Minute).Truncate(time.Second), time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	params := url.Values{"from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}, "visitor": {visitor}}
	path := "/api/analytics/sites/" + site.ID + "/sessions/" + session + "/activity?" + params.Encode()
	request := func(path string, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	adminCookie := cookie(admin.Username)
	if w := request(path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(path, cookie(viewer.Username)); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(path, adminCookie); w.Code != 409 {
		t.Fatal("without signed receipt", w.Code)
	}
	if _, err := a.Store.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,target,version,sha256,updated_at) VALUES('website-analytics','website-analytics','website-analytics',?,?,?)`,
		appcatalog.AnalyticsSessionActivityVersion, strings.Repeat("a", 64), Now()); err != nil {
		t.Fatal(err)
	}

	if w := request(path+"&visitor="+visitor, adminCookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(strings.Replace(path, visitor, ID()+ID(), 1), adminCookie); w.Code != 404 {
		t.Fatal(w.Code)
	}
	w := request(path, adminCookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	var result analyticsSessionActivity
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 3 || result.Events[0].Path != "/cart" || result.Events[0].Kind != "pageview" || result.Events[1].Kind != "click" || result.Events[1].X == nil || *result.Events[1].X != 0 || *result.Events[1].Y != 62.5 || result.Events[2].Duration == nil || *result.Events[2].Duration != 4.5 || result.Partial {
		t.Fatal(w.Body.String())
	}
	for _, forbidden := range []string{"private-title", "private-value", "private-source", "other-private", "another-visitor", visitor, "page_id", "ip_hash"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("private analytics field disclosed", forbidden)
		}
	}
	for i := 0; i < analyticsSessionActivityLimit; i++ {
		funnelEvent(t, a.Store, site.ID, visitor, session, ID(), "/recent", time.Now().Unix())
	}
	w = request(path, adminCookie)
	result = analyticsSessionActivity{}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Partial || len(result.Events) != analyticsSessionActivityLimit || result.Events[0].Path != "/recent" {
		t.Fatal(w.Code, len(result.Events), result.Partial)
	}
}
