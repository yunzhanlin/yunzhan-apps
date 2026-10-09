package core

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyticsAutoHostExactSiteAliasesAndNumericPorts(t *testing.T) {
	site := Site{Domain: "analytics.example", Settings: SiteSettings{Domains: []string{"alias.example"}}}
	for _, host := range []string{"analytics.example", "ANALYTICS.example", "alias.example:443", "analytics.example:19101"} {
		if !analyticsAutoHost(site, host) {
			t.Fatal("legitimate same-site host", host)
		}
	}
	for _, host := range []string{"evil.example", "analytics.example.evil", "127.0.0.1:19100", "analytics.example@evil.example", "analytics.example:", "analytics.example:no", "analytics.example:0", "analytics.example:65536", "analytics.example:0443", "https://analytics.example", "analytics.example/", "[::1]:443"} {
		if analyticsAutoHost(site, host) {
			t.Fatal("untrusted/malformed host", host)
		}
	}
}

func TestAnalyticsAutoScriptRequiresAppliedSiteAndEnabledPublicCollector(t *testing.T) {
	a, site, cfg := analyticsFixture(t, true)
	settings := DefaultSiteSettings(site.Settings)
	settings.AnalyticsInjectHTML = true
	settings.AnalyticsEndpoint = "127.0.0.1:19100"
	settings.Domains = []string{"alias.example"}
	apply := func(status string, enabled bool) {
		t.Helper()
		settings.AnalyticsInjectHTML = enabled
		data, _ := json.Marshal(settings)
		if _, err := a.Store.DB.Exec(`UPDATE sites SET settings_json=?,status=? WHERE id=?`, string(data), status, site.ID); err != nil {
			t.Fatal(err)
		}
	}
	request := func(host, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/collect/analytics/auto.js?site="+id, nil)
		r.Host = host
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	apply("running", true)
	for _, host := range []string{"analytics.example", "alias.example:443"} {
		w := request(host, site.ID)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), cfg.Key) {
			t.Fatal("first-party public script", w.Code, w.Header())
		}
	}
	for _, host := range []string{"evil.example", "127.0.0.1:19100", "analytics.example:bad"} {
		if w := request(host, site.ID); w.Code != 404 || strings.Contains(w.Body.String(), cfg.Key) {
			t.Fatal("wrong-host key disclosure", host, w.Code)
		}
	}
	if w := request("analytics.example", ID()); w.Code != 404 {
		t.Fatal("unknown site", w.Code)
	}
	apply("stopped", true)
	if w := request("analytics.example", site.ID); w.Code != 404 {
		t.Fatal("stopped site", w.Code)
	}
	apply("running", false)
	if w := request("analytics.example", site.ID); w.Code != 404 {
		t.Fatal("opted-out site", w.Code)
	}
	apply("running", true)
	cfg.Enabled = false
	if _, err := a.Store.saveAnalyticsConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if w := request("analytics.example", site.ID); w.Code != 404 {
		t.Fatal("disabled collector", w.Code)
	}
}

func TestAnalyticsAutoIntentRejectedBeforeQueueAndPreservedByOldEditor(t *testing.T) {
	s := testStore(t)
	site := settingsSite(t, s, "analytics-html-intent")
	settings := site.Settings
	settings.AnalyticsEndpoint = "127.0.0.1:19100"
	settings.AnalyticsInjectHTML = true
	yes, no := true, false
	cfg := AnalyticsConfig{SiteID: site.ID, Enabled: true, Retention: 30, AutoInjectHTML: &no}
	if _, err := s.queueSiteSettings(site.ID, settings, 0, Hash("current"), ID(), "admin", &cfg); err == nil {
		t.Fatal("mismatched intent enqueued")
	}
	cfg.AutoInjectHTML = &yes
	cfg.SiteID = ID()
	if _, err := s.queueSiteSettings(site.ID, settings, 0, Hash("current"), ID(), "admin", &cfg); err == nil {
		t.Fatal("wrong-site intent enqueued")
	}
	cfg.SiteID = site.ID
	job, err := s.queueSiteSettings(site.ID, settings, 0, Hash("current"), ID(), "admin", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.NextJob()
	if err != nil || pending.ID != job {
		t.Fatal(err)
	}
	if err := s.Finish(pending, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	current, _ := s.Site(site.ID)
	old := current.Settings
	old.AnalyticsInjectHTML = false
	old.AnalyticsEndpoint = ""
	old.IndexFiles = []string{"home.html"}
	if _, err := s.QueueSiteSettings(site.ID, old, current.SettingsRevision, Hash("current"), ID(), "admin"); err != nil {
		t.Fatal(err)
	}
	pending, err = s.NextJob()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(pending, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	current, _ = s.Site(site.ID)
	if !current.Settings.AnalyticsInjectHTML || current.Settings.AnalyticsEndpoint != "127.0.0.1:19100" || current.Settings.IndexFiles[0] != "home.html" {
		t.Fatal("older site editor dropped opt-in or proxy")
	}
	base := AnalyticsConfig{SiteID: site.ID, Enabled: true, Retention: 30, AutoInjectHTML: &yes}
	omitted := base
	omitted.AutoInjectHTML = nil
	if !sameAnalyticsRequest(omitted, base) {
		t.Fatal("omitted retry changed intent")
	}
	explicit := base
	explicit.AutoInjectHTML = &no
	if sameAnalyticsRequest(explicit, base) {
		t.Fatal("explicit different retry reused a key")
	}
}
