//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAF220UpgradePreservesTrustedProxyAndPausedBodyWithScopedCC(t *testing.T) {
	for _, mode := range []string{"block", "observe", "off"} {
		t.Run(mode, func(t *testing.T) {
			id := core.ID()
			s, original := wafLegacyVersionFixture(t, "2.2.0", func(cfg *core.WAFConfig) {
				cfg.TrustedProxy = wafTrustedProxyFixture()
				body := core.DefaultWAFBodyPolicy()
				body.Mode = "off"
				cfg.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{{SiteID: id, Policy: body}}}
				cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: id, Mode: mode}}
			})
			s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
				if len(args) == 1 && args[0] == "-V" {
					return "configure arguments: --with-http_realip_module", nil
				}
				return "", nil
			}
			manifest, _ := s.readSoftwareManifest("nginx-waf")
			path := filepath.Join(s.Config.ConfDir, id+".conf")
			before, _ := os.ReadFile(path)
			if strings.Contains(string(before), wafCCSiteBegin) {
				t.Fatal("historical renderer added new CC behavior")
			}
			if !s.softwareStatus(context.Background(), "nginx-waf").Healthy {
				t.Fatal("valid historical 2.2.0 no longer readable")
			}
			if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err != nil {
				t.Fatal(err)
			}
			afterManifest, _ := s.readSoftwareManifest("nginx-waf")
			after, _ := core.DecodeWAFConfig(afterManifest.Settings)
			original.Policy.Revision++
			want, _ := json.Marshal(original)
			got, _ := json.Marshal(after)
			if !bytes.Equal(want, got) || afterManifest.InstalledAt != manifest.InstalledAt || afterManifest.Version != core.WAFVersion {
				t.Fatal("policy, trust or engine lost during upgrade")
			}
			actual, _ := os.ReadFile(path)
			expected, err := renderWAFCCSite(string(before), id, mode, true)
			if err != nil || string(actual) != expected {
				t.Fatal("upgrade changed unrelated website bytes", err)
			}
			if !s.softwareStatus(context.Background(), "nginx-waf").Healthy {
				t.Fatal("new CC configuration unhealthy")
			}
			recreated := core.Site{ID: id, Domain: "cc-edit.localhost"}
			fresh, err := renderSiteConfig(recreated, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			fresh, err = s.preserveWAFBodySiteConfig(fresh, id)
			if err != nil || !strings.Contains(fresh, wafCCSiteBegin+wafCCSiteLines(mode)+wafCCSiteEnd) {
				t.Fatal("website edit dropped scoped CC mode", err)
			}
		})
	}
}

func TestWAFCCObservationConflictNeverWritesAndRejectsScopeDrift(t *testing.T) {
	s := wafPolicyFixture(t)
	id := core.ID()
	path := filepath.Join(s.Config.ConfDir, id+".conf")
	base := "# managed by panel; site=" + id + "\nserver {\n  include /etc/panel/waf/server.d/*.conf;\n}\n"
	if err := os.WriteFile(path, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.applyWAF(context.Background(), nil, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	manifest, _ := s.readSoftwareManifest("nginx-waf")
	cfg, _ := core.DecodeWAFConfig(manifest.Settings)
	cfg.Policy.Mode = "observe"
	_, server := wafFiles(s)
	foreign := filepath.Join(filepath.Dir(server), "admin.conf")
	if err := os.WriteFile(foreign, []byte("limit_req zone=admin;\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	oldManifest, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if _, err := s.planWAFConfiguration(cfg, false); err == nil {
		t.Fatal("external server include accepted")
	}
	got, _ := os.ReadFile(path)
	currentManifest, _ := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if !bytes.Equal(got, before) || !bytes.Equal(currentManifest, oldManifest) {
		t.Fatal("rejected preview wrote active state")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	drift := strings.Replace(string(before), wafCCSiteLines("block"), wafCCSiteLines("observe"), 1)
	if err := os.WriteFile(path, []byte(drift), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.planWAFConfiguration(cfg, false); err == nil {
		t.Fatal("externally changed scope adopted as previous policy")
	}
}
