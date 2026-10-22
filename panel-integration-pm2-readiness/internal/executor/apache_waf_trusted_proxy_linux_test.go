//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApacheWAFConfigSaveCannotImplicitlyUpgradeOlderApp(t *testing.T) {
	s := wafPolicyFixture(t)
	path := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 4
	if err := moduleWrite(path, map[string]any{"version": "2.0.0", "settings": core.WAFSettings(cfg)}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("version gate ran a native mutation command")
		return "", nil
	}
	err = s.applyApacheWAF(context.Background(), core.WAFSettings(cfg), false, false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "签名升级") {
		t.Fatal("ordinary save could promote older application", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("version refusal mutated installation evidence", err)
	}
	if _, err := os.Stat(filepath.Join(s.moduleDir("apache-waf"), "config-backups")); !os.IsNotExist(err) {
		t.Fatal("version refusal began backups/mutations", err)
	}
}

func TestApacheWAFTrustedProxyPreserveRevisionAndVersionGate(t *testing.T) {
	s := wafPolicyFixture(t)
	path := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 9
	cfg.TrustedProxy = apacheTrustedProxyFixture()
	if err := moduleWrite(path, map[string]any{"version": core.ApacheWAFVersion, "settings": core.WAFSettings(cfg)}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	raw := core.WAFSettings(cfg)
	delete(raw, "trusted_proxy")
	raw["profile"] = "strict"
	got, err := s.apacheWAFSettings(raw, false)
	if err != nil || !reflect.DeepEqual(got.TrustedProxy, cfg.TrustedProxy) || got.Policy.Revision != 9 {
		t.Fatal(got, err)
	}
	got, err = s.apacheWAFSettings(map[string]any{"profile": "strict", "rate_per_second": 30}, false)
	if err != nil || !reflect.DeepEqual(got.TrustedProxy, cfg.TrustedProxy) || got.Policy.Revision != 9 {
		t.Fatal("legacy omission erased proxy", got, err)
	}
	stale := cfg
	stale.Policy.Revision--
	if _, err := s.apacheWAFSettings(core.WAFSettings(stale), false); err == nil {
		t.Fatal("stale policy accepted")
	}
	if _, err := s.apacheWAFSettings(map[string]any{"trusted_proxy": raw["trusted_proxy"]}, false); err == nil {
		t.Fatal("unrevisioned policy accepted")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("validation mutated installed evidence")
	}
	cfg.TrustedProxy.Enabled = false
	got, err = s.apacheWAFSettings(core.WAFSettings(cfg), false)
	if err != nil || got.TrustedProxy.Enabled {
		t.Fatal("explicit disable not accepted", got, err)
	}
	cfg.TrustedProxy = nil
	if err := moduleWrite(path, map[string]any{"version": "2.0.0", "settings": core.WAFSettings(cfg)}); err != nil {
		t.Fatal(err)
	}
	cfg.TrustedProxy = apacheTrustedProxyFixture()
	if _, err := s.apacheWAFSettings(core.WAFSettings(cfg), false); err == nil {
		t.Fatal("old app falsely claimed new implementation")
	}
}

func TestApacheWAFTrustedProxyUnsafeModulePathRefused(t *testing.T) {
	for _, path := range []string{"relative.so", "/missing-panel-apache-module.so", "/tmp/../unknown.so"} {
		if verifyApacheWAFRemoteIPModule(path) == nil {
			t.Fatal("unsafe module path accepted", path)
		}
	}
	path := filepath.Join(t.TempDir(), "linked.so")
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if verifyApacheWAFRemoteIPModule(path) == nil {
		t.Fatal("linked library accepted")
	}
}
