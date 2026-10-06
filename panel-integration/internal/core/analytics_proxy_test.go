package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyticsProxyBaselineAllowsOnlyGeneratedProofHashDrift(t *testing.T) {
	id := strings.Repeat("a", 32)
	oldHash, newHash := strings.Repeat("1", 64), strings.Repeat("2", 64)
	current := "server {\n  location = /__panel_health_" + id + ` { default_type text/plain; access_log off; return 200 "panel:` + id + ":" + oldHash + `"; }` + "\n" + `  add_header X-Panel-Config "` + oldHash + `" always;` + "\n  location / { try_files $uri $uri/ =404; }\n}\n"
	candidate := strings.ReplaceAll(current, oldHash, newHash)
	if !sameManagedAnalyticsBaseline(current, candidate, id) {
		t.Fatal("legacy managed proof hashes prevented automatic proxy installation")
	}
	for _, edited := range []string{
		strings.Replace(current, "=404", "=403", 1),
		strings.Replace(current, "return 200", "return 302", 1),
		strings.Replace(current, "always;", ";", 1),
		strings.Replace(current, "panel:"+id, "panel:"+strings.Repeat("b", 32), 1),
		strings.Replace(current, oldHash, "not-a-generated-proof", 1),
		strings.Replace(current, oldHash, strings.Repeat("z", 64), 1),
		strings.Replace(current, "server {", "server {\n  add_header X-Custom preserved;", 1),
	} {
		if sameManagedAnalyticsBaseline(edited, candidate, id) {
			t.Fatal("manual configuration edit ignored", edited)
		}
	}
}

func TestAnalyticsProxyLoopbackOnly(t *testing.T) {
	for _, address := range []string{"127.0.0.1:19100", "127.0.0.1:19220", "[::1]:8888"} {
		if err := ValidateAnalyticsEndpoint(address); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{"localhost:19100", "0.0.0.0:19100", "192.0.2.1:19100", "example.com:80", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:019100", "127.0.0.1:19100;include /etc/passwd", "http://127.0.0.1:19100/"} {
		if ValidateAnalyticsEndpoint(address) == nil {
			t.Fatal("unsafe endpoint accepted", address)
		}
	}
}

func TestAnalyticsProxyCommitsOnlyAfterSiteApplyAndPreservesOtherSettings(t *testing.T) {
	s := testStore(t)
	site := settingsSite(t, s, "analytics-auto")
	cfg, err := s.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: site.ID, Retention: 30})
	if err != nil {
		t.Fatal(err)
	}
	settings := site.Settings
	settings.AnalyticsEndpoint = "127.0.0.1:19220"
	cfg.Enabled = true
	job, err := s.queueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("old"), "enable-auto", "admin", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, _ := s.analyticsConfig(site.ID)
	if unchanged.Enabled {
		t.Fatal("reported enabled before actual reload")
	}
	duplicate, err := s.queueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("old"), "enable-auto", "admin", &cfg)
	if err != nil || duplicate != job {
		t.Fatal("duplicate request", err)
	}
	pending, err := s.NextJob()
	if err != nil || pending.ID != job {
		t.Fatal(err)
	}
	if err = s.Finish(pending, "running", "simulated syntax failure", nil); err != nil {
		t.Fatal(err)
	}
	unchanged, _ = s.analyticsConfig(site.ID)
	current, _ := s.Site(site.ID)
	if unchanged.Enabled || current.Settings.AnalyticsEndpoint != "" || current.SettingsRevision != 0 {
		t.Fatal("failed reload committed configuration")
	}
	if err = s.Retry(job, "admin"); err != nil {
		t.Fatal(err)
	}
	pending, err = s.NextJob()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(pending, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.analyticsConfig(site.ID)
	current, _ = s.Site(site.ID)
	if !cfg.Enabled || cfg.Revision != 2 || current.Settings.AnalyticsEndpoint != "127.0.0.1:19220" {
		t.Fatal(cfg, current)
	}
	// An older ordinary settings editor omits the new internal property.
	normal := current.Settings
	normal.AnalyticsEndpoint = ""
	normal.IndexFiles = []string{"home.html"}
	edit, err := s.QueueSiteSettings(site.ID, normal, current.SettingsRevision, Hash("enabled"), "ordinary-edit", "admin")
	if err != nil {
		t.Fatal(err)
	}
	pending, _ = s.NextJob()
	if pending.ID != edit {
		t.Fatal("wrong job")
	}
	if err = s.Finish(pending, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	current, _ = s.Site(site.ID)
	if current.Settings.AnalyticsEndpoint != "127.0.0.1:19220" {
		t.Fatal("ordinary editor removed proxy")
	}
	cfg.Enabled = false
	settings = current.Settings
	settings.AnalyticsEndpoint = ""
	_, err = s.queueSiteSettings(site.ID, settings, current.SettingsRevision, Hash("enabled"), "disable-auto", "admin", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	pending, _ = s.NextJob()
	if err = s.Finish(pending, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	disabled, _ := s.analyticsConfig(site.ID)
	current, _ = s.Site(site.ID)
	if disabled.Enabled || disabled.Key != cfg.Key || current.Settings.AnalyticsEndpoint != "" || current.Settings.IndexFiles[0] != "home.html" {
		t.Fatal("disable failed or changed unrelated settings", disabled, current)
	}
}

func TestAnalyticsProxyRejectsStaleRevisionAndConcurrentSiteJobs(t *testing.T) {
	s := testStore(t)
	site := settingsSite(t, s, "analytics-revision")
	cfg := AnalyticsConfig{SiteID: site.ID, Enabled: true, Retention: 30, Revision: 7}
	settings := site.Settings
	settings.AnalyticsEndpoint = "127.0.0.1:19100"
	if _, err := s.queueSiteSettings(site.ID, settings, 0, Hash("old"), ID(), "admin", &cfg); err == nil {
		t.Fatal("stale analytics revision accepted")
	}
	cfg.Revision = 0
	job, err := s.queueSiteSettings(site.ID, settings, 0, Hash("old"), ID(), "admin", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.QueueSiteSettings(site.ID, site.Settings, 0, Hash("old"), ID(), "admin"); err == nil {
		t.Fatal("concurrent site writer accepted")
	}
	var payload string
	_ = s.DB.QueryRow(`SELECT payload FROM jobs WHERE id=?`, job).Scan(&payload)
	var p JobPayload
	_ = json.Unmarshal([]byte(payload), &p)
	if p.Analytics == nil || p.Analytics.SiteID != site.ID || p.Settings.AnalyticsEndpoint == "" {
		t.Fatal("missing durable configuration payload")
	}
}
