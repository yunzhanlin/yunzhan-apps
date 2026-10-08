//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func wafTrustedProxyFixture() *core.WAFTrustedProxyConfig {
	return &core.WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"127.0.0.1/32", "2001:db8::/32"}, AcknowledgeHeaderControl: true}
}

func TestWAFTrustedProxyRequiresExactCurrentModuleBeforeWrites(t *testing.T) {
	for _, output := range []string{"", "--with-http_realip_module=no", "--with-http_realip_module-extra", "--with-stream_realip_module", strings.Repeat("x", 65537), "configure arguments: '--with-http_realip_module'"} {
		t.Run(strings.TrimSpace(output[:min(len(output), 48)]), func(t *testing.T) {
			s := wafPolicyFixture(t)
			cfg := core.DefaultWAFConfig()
			cfg.TrustedProxy = wafTrustedProxyFixture()
			calls := 0
			s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok || name != s.Config.NginxBin || len(args) != 1 || args[0] != "-V" {
					t.Fatal("unbounded or unrelated module check", name, args)
				}
				return output, nil
			}
			valid := strings.Contains(output, "'--with-http_realip_module'")
			err := s.verifyWAFTrustedProxy(context.Background(), cfg, s.Config.NginxBin)
			if (err == nil) != valid || calls != 1 {
				t.Fatal("module proof mismatch", err, calls)
			}
			if !valid {
				if s.applyWAFTransaction(context.Background(), cfg, false, s.Config.NginxBin, func(string) {}) == nil {
					t.Fatal("unverified module accepted")
				}
				for _, path := range []string{s.softwareManifestPath("nginx-waf"), s.wafPendingPath(), filepath.Join(s.Config.SecurityDir, "waf-backups")} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("module rejection created mutation/evidence", path, err)
					}
				}
			}
		})
	}
	s := wafPolicyFixture(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("disabled policy ran command")
		return "", nil
	}
	for _, proxy := range []*core.WAFTrustedProxyConfig{nil, {Header: "X-Forwarded-For", TrustedCIDRs: []string{}}} {
		cfg := core.DefaultWAFConfig()
		cfg.TrustedProxy = proxy
		if err := s.verifyWAFTrustedProxy(context.Background(), cfg, s.Config.NginxBin); err != nil {
			t.Fatal(err)
		}
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		return "--with-http_realip_module", errors.New("failed command")
	}
	cfg := core.DefaultWAFConfig()
	cfg.TrustedProxy = wafTrustedProxyFixture()
	if s.verifyWAFTrustedProxy(context.Background(), cfg, s.Config.NginxBin) == nil {
		t.Fatal("failed command output trusted")
	}
}

func TestWAFTrustedProxyPreserveReplayAndExplicitDisable(t *testing.T) {
	s := wafPolicyFixture(t)
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) == 1 && args[0] == "-V" {
			return "configure arguments: --with-http_realip_module", nil
		}
		return "", nil
	}
	initial := core.DefaultWAFConfig()
	initial.TrustedProxy = wafTrustedProxyFixture()
	if err := s.applyWAF(context.Background(), core.WAFSettings(initial), true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	manifest, _ := s.readSoftwareManifest("nginx-waf")
	cfg, _ := core.DecodeWAFConfig(manifest.Settings)
	raw := core.WAFSettings(cfg)
	delete(raw, "trusted_proxy")
	raw["profile"] = "strict"
	if err := s.applyWAF(context.Background(), raw, false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err := s.applyWAF(context.Background(), raw, false, func(string) {}); err != nil {
		t.Fatal("lost acknowledgement replay failed", err)
	}
	manifest, _ = s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	if cfg.Policy.Revision != 2 || cfg.TrustedProxy == nil || !cfg.TrustedProxy.Enabled {
		t.Fatal("omission erased trust or replay bumped revision", cfg)
	}
	if _, err := s.prepareWAFSettings(map[string]any{"trusted_proxy": core.WAFSettings(cfg)["trusted_proxy"]}, false); err == nil {
		t.Fatal("unrevisioned trust accepted")
	}
	if err := s.applyWAF(context.Background(), map[string]any{"profile": "balanced", "rate_per_second": 30}, false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	manifest, _ = s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	if cfg.TrustedProxy == nil || !cfg.TrustedProxy.Enabled {
		t.Fatal("legacy client erased trust")
	}
	h, v := wafFiles(s)
	paths := []string{h, v, s.Config.NginxConf, s.softwareManifestPath("nginx-waf")}
	before := map[string][]byte{}
	for _, path := range paths {
		before[path], _ = os.ReadFile(path)
	}
	stale := cfg
	stale.Policy.Revision--
	stale.TrustedProxy = &core.WAFTrustedProxyConfig{Header: "X-Forwarded-For", TrustedCIDRs: []string{}}
	if err := s.applyWAF(context.Background(), core.WAFSettings(stale), false, func(string) {}); err == nil {
		t.Fatal("stale disable accepted")
	}
	for path, want := range before {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, want) {
			t.Fatal("stale policy wrote", path)
		}
	}
	cfg.TrustedProxy = stale.TrustedProxy
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) == 1 && args[0] == "-V" {
			t.Fatal("disabled config requires module")
		}
		if name == s.Config.NginxBin {
			return "", errors.New("synthetic syntax failure")
		}
		return "", nil
	}
	if err := s.applyWAF(context.Background(), core.WAFSettings(cfg), false, func(string) {}); err == nil {
		t.Fatal("syntax failure accepted")
	}
	for path, want := range before {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, want) {
			t.Fatal("rollback lost trust", path)
		}
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "", nil }
	if err := s.applyWAF(context.Background(), core.WAFSettings(cfg), false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	server, _ := os.ReadFile(v)
	http, _ := os.ReadFile(h)
	if strings.Contains(string(server), "real_ip_") || strings.Contains(string(server), "set_real_ip_from") || strings.Contains(string(http), "realip_remote_addr") {
		t.Fatal("explicit disable left managed trust/peer variable")
	}
}

func TestWAFTrustedProxyCannotClaimLegacyPackageCapability(t *testing.T) {
	s, cfg := wafLegacyVersionFixture(t, "2.1.1")
	cfg.TrustedProxy = wafTrustedProxyFixture()
	if _, err := s.prepareWAFSettings(core.WAFSettings(cfg), false); err == nil {
		t.Fatal("old installed package claimed new capability")
	}
	for _, version := range []string{"2.0.1", "2.1.0", "2.1.1"} {
		if wafHistoricalVersionValid(version, cfg) {
			t.Fatal("new policy attributed to historical version", version)
		}
	}
}
