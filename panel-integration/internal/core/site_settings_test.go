package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func settingsSite(t *testing.T, s *Store, slug string) Site {
	t.Helper()
	_, e := s.CreateSite(slug, slug, ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	site, e := s.Site(j.SiteID)
	if e != nil {
		t.Fatal(e)
	}
	return site
}
func TestWebsiteSettingsTransactionsAndDomainReservations(t *testing.T) {
	s := testStore(t)
	site := settingsSite(t, s, "settings-one")
	other := settingsSite(t, s, "settings-two")
	config := DefaultSiteSettings(SiteSettings{Domains: []string{"alias.example.test"}, Mode: "redirect", RedirectURL: "https://example.test", PreserveURI: true})
	job, e := s.QueueSiteSettings(site.ID, config, 0, Hash("current"), "settings-key", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.QueueSiteSettings(site.ID, config, 0, Hash("current"), "settings-key", "admin")
	if e != nil || same != job {
		t.Fatal("idempotency", e)
	}
	if _, e = s.QueueSiteSettings(other.ID, config, 0, Hash("other"), "conflict-key", "admin"); e == nil {
		t.Fatal("pending domain reservation ignored")
	}
	if _, e = s.CreateSite("alias", "alias", ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	pending, e := s.NextJob()
	if e != nil || pending.ID != job {
		t.Fatal("wrong configured job", e)
	}
	if e = s.Finish(pending, "needs_attention", "simulated failure", nil); e != nil {
		t.Fatal(e)
	}
	existing, _ := s.Site(site.ID)
	if existing.SettingsRevision != 0 || existing.Settings.Mode != "files" {
		t.Fatal("failed settings replaced persisted configuration")
	}
	if _, e = s.QueueSiteSettings(other.ID, config, 0, Hash("other"), ID(), "admin"); e == nil {
		t.Fatal("failed unverified domain reservation was discarded")
	}
	if e = s.Retry(job, "admin"); e != nil {
		t.Fatal(e)
	}
	pending, e = s.NextJob()
	if e != nil || pending.ID != job {
		t.Fatal("retry did not return same settings", e)
	}
	if e = s.Finish(pending, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	existing, _ = s.Site(site.ID)
	if existing.SettingsRevision != 1 || existing.Settings.Mode != "redirect" {
		t.Fatal("successful settings not committed")
	}
	if _, e = s.QueueSiteSettings(site.ID, config, 0, Hash("current"), ID(), "admin"); e == nil {
		t.Fatal("stale revision accepted")
	}
	if e = s.Retry(job, "admin"); e == nil {
		t.Fatal("obsolete configuration replay accepted")
	}
	var payload string
	s.DB.QueryRow(`SELECT payload FROM jobs WHERE id=?`, job).Scan(&payload)
	var p JobPayload
	if json.Unmarshal([]byte(payload), &p) != nil || p.Settings == nil {
		t.Fatal("missing durable settings payload")
	}
}
func TestSettingsCannotStealPrimaryDomainOrInjectConfiguration(t *testing.T) {
	s := testStore(t)
	site := settingsSite(t, s, "primary-one")
	other := settingsSite(t, s, "primary-two")
	if _, e := s.QueueSiteSettings(site.ID, SiteSettings{Domains: []string{other.Domain}}, 0, Hash("config"), ID(), "admin"); e == nil {
		t.Fatal("primary domain stolen")
	}
	if _, e := s.QueueSiteSettings(site.ID, SiteSettings{Domains: []string{"reserved-new.localhost"}}, 0, Hash("config"), ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CreateSite("collision", "reserved-new", ID(), "admin"); e == nil {
		t.Fatal("new site stole reserved alias")
	}
	cases := []SiteSettings{
		{Domains: []string{"safe.test;include /etc/passwd"}}, {DocumentRoot: "../private"}, {DocumentRoot: "app/$host"}, {IndexFiles: []string{"index.html;"}},
		{Mode: "proxy", ProxyURL: "http://127.0.0.1:19100"}, {Mode: "proxy", ProxyURL: "http://169.254.169.254/latest"}, {Mode: "proxy", ProxyURL: "http://user:password@example.test"},
		{Mode: "redirect", RedirectURL: "https://example.test/$host"}, {Mode: "redirect", RedirectURL: "https://example.test/path", PreserveURI: true},
		{Rewrite: "custom", Rules: []RewriteRule{{Pattern: "^/x", Replacement: "/index.php?$http_authorization", Flag: "last"}}},
		{Rewrite: "custom", Rules: []RewriteRule{{Pattern: "^/x\";}", Replacement: "/index.php", Flag: "last"}}},
	}
	for _, c := range cases {
		if e := ValidateSiteSettings(c, site.Domain, "php-8.4.25"); e == nil {
			t.Fatalf("unsafe config accepted: %+v", c)
		}
	}
	safe := SiteSettings{Domains: []string{"www.example.test"}, DocumentRoot: "app/public", Rewrite: "custom", Rules: []RewriteRule{{Pattern: `^/item/([0-9]+)$`, Replacement: "/index.php?id=$1&$args", Flag: "last"}}}
	if e := ValidateSiteSettings(safe, site.Domain, "php-8.4.25"); e != nil {
		t.Fatal("safe custom rewrite rejected", e)
	}
	for _, host := range []string{"", strings.Repeat("a", 64) + ".test", "UPPER.test", "example.test.", "*.example.test", "127.0.0.1"} {
		if ValidDomain(host) {
			t.Fatal("invalid domain accepted", host)
		}
	}
}
