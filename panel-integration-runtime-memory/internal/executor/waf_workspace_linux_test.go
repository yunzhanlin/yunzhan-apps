//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wafPolicyFixture(t *testing.T) *Service {
	t.Helper()
	s := testService(t, func(context.Context, string, ...string) (string, error) { return "", nil })
	s.Config.SystemRoot = t.TempDir()
	s.Config.SecurityDir = filepath.Join(s.Config.SystemRoot, "security")
	s.Config.NginxConf = filepath.Join(s.Config.SystemRoot, "nginx.conf")
	if e := os.WriteFile(s.Config.NginxConf, []byte("events {}\nhttp {\n}\n"), 0644); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestWAFRevisionReplayLegacyAndRollback(t *testing.T) {
	s := wafPolicyFixture(t)
	site := core.Site{ID: core.ID(), Domain: "waf-policy.localhost"}
	content, e := renderSiteConfig(site, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	sitePath := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	if e = os.WriteFile(sitePath, []byte(content), 0644); e != nil {
		t.Fatal(e)
	}
	if e = s.applyWAF(context.Background(), nil, true, func(string) {}); e != nil {
		t.Fatal(e)
	}
	manifest, e := s.readSoftwareManifest("nginx-waf")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := core.DecodeWAFConfig(manifest.Settings)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Policy.Revision != 1 || manifest.Version != core.WAFVersion {
		t.Fatal("missing real migration", manifest)
	}
	cfg.Policy.Lists["ua_deny"] = []core.WAFEntry{{ID: core.ID(), Value: "test scanner", SiteID: site.ID}}
	raw := core.WAFSettings(cfg)
	if e = s.applyWAF(context.Background(), raw, false, func(string) {}); e != nil {
		t.Fatal(e)
	}
	if e = s.applyWAF(context.Background(), raw, false, func(string) {}); e != nil {
		t.Fatal("successful lost-ack retry rejected", e)
	}
	manifest, _ = s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	if cfg.Policy.Revision != 2 {
		t.Fatal("replay created another revision")
	}
	stale := core.WAFSettings(cfg)
	staleCfg := cfg
	staleCfg.Policy.Revision = 0
	staleCfg.Profile = "strict"
	if e = s.applyWAF(context.Background(), core.WAFSettings(staleCfg), false, func(string) {}); e == nil {
		t.Fatal("different stale draft accepted")
	}
	if e = s.applyWAF(context.Background(), map[string]any{"profile": "strict", "rate_per_second": 30}, false, func(string) {}); e != nil {
		t.Fatal(e)
	}
	manifest, _ = s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	if len(cfg.Policy.Lists["ua_deny"]) != 1 || cfg.Rate != 30 {
		t.Fatal("legacy client erased advanced policy", cfg)
	}
	h, v := wafFiles(s)
	oldH, _ := os.ReadFile(h)
	oldV, _ := os.ReadFile(v)
	oldSite, _ := os.ReadFile(sitePath)
	oldMain, _ := os.ReadFile(s.Config.NginxConf)
	oldManifest, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == s.Config.NginxBin {
			return "", errors.New("synthetic nginx -t failure")
		}
		return "", nil
	}
	cfg.Profile = "balanced"
	if e = s.applyWAF(context.Background(), core.WAFSettings(cfg), false, func(string) {}); e == nil {
		t.Fatal("invalid configuration reported applied")
	}
	for path, want := range map[string][]byte{h: oldH, v: oldV, sitePath: oldSite, s.Config.NginxConf: oldMain, s.softwareManifestPath("nginx-waf"): oldManifest} {
		got, _ := os.ReadFile(path)
		if string(got) != string(want) {
			t.Fatal("rollback changed previous configuration", path)
		}
	}
	_ = stale
	backups, e := os.ReadDir(filepath.Join(s.Config.SecurityDir, "waf-backups"))
	if e != nil || len(backups) != 4 {
		t.Fatal("persistent evidence missing or replay duplicated backup", len(backups), e)
	}
}
func TestWAFIncludesMigrateWithoutChangingOptOut(t *testing.T) {
	s := wafPolicyFixture(t)
	id := core.ID()
	path := filepath.Join(s.Config.ConfDir, id+".conf")
	old := "# managed by panel; site=" + id + "\nserver {\n  include /etc/panel/waf/server.d/*.conf;\n}\nserver {\n  include /etc/panel/waf/server.d/*.conf;\n}\n"
	os.WriteFile(path, []byte(old), 0644)
	if _, e := s.ensureWAFIncludes(); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(path)
	if strings.Count(string(got), "set $panel_waf_site "+id) != 2 {
		t.Fatal("TLS and HTTP server scopes not migrated")
	}
}

func TestWAFBodyPolicySurvivesOlderClientWithoutSilentErase(t *testing.T) {
	s := wafPolicyFixture(t)
	id := core.ID()
	path := filepath.Join(s.Config.ConfDir, id+".conf")
	if err := os.WriteFile(path, []byte("# managed by panel; site="+id+"\nserver {\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	old := core.DefaultWAFConfig()
	old.Policy.Revision = 7
	body := core.DefaultWAFBodyPolicy()
	body.Mode = "off"
	old.Body = &core.WAFBodyConfig{Sites: []core.WAFBodySitePolicy{{SiteID: id, Policy: body}}}
	if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, Settings: core.WAFSettings(old), InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []map[string]any{{"profile": "strict", "rate_per_second": 30}, core.WAFSettings(core.WAFConfig{Profile: old.Profile, Rate: old.Rate, Policy: old.Policy})} {
		got, err := s.prepareWAFSettings(raw, false)
		if err != nil || got.Body == nil || len(got.Body.Sites) != 1 || got.Body.Sites[0].SiteID != id {
			t.Fatal("older client erased independent body policy", err)
		}
	}
	if _, err := s.prepareWAFSettings(map[string]any{"body": map[string]any{"sites": []any{}, "engine_job_id": ""}}, false); err == nil {
		t.Fatal("body-only legacy request silently dropped")
	}
}
