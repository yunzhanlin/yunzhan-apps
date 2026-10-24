//go:build linux

package executor

import (
	"bytes"
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApacheWAFReplayNonCandidateNeverConfirmsOrMutates(t *testing.T) {
	s := wafPolicyFixture(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("non-candidate replay issued a native command")
		return "", nil
	}
	for _, raw := range []map[string]any{nil, {"profile": "strict"}, {"policy": "invalid"}} {
		if match, err := s.confirmApacheWAFReplay(context.Background(), raw); match || err != nil {
			t.Fatal("ordinary request falsely confirmed as persisted replay", match, err)
		}
	}
	if _, err := os.Lstat(s.moduleDir("apache-waf")); !os.IsNotExist(err) {
		t.Fatal("non-candidate created an application directory", err)
	}
}

func requireApacheReplayInstalled(t *testing.T) *Service {
	t.Helper()
	if os.Getenv("PANEL_QA_APACHE_REPLAY_INSTALLED") != "1" {
		t.Skip("explicit isolated installed Apache read-only replay QA required")
	}
	if _, err := apacheRelease(); err != nil {
		t.Fatal("requested pinned runtime absent", err)
	}
	return New(Config{Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("read-only replay attempted a native mutation")
		return "", nil
	}})
}

func TestApacheWAFReplayActuallyLoadedInstallationIsReadOnly(t *testing.T) {
	s := requireApacheReplayInstalled(t)
	var installed struct {
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err := moduleRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), &installed); err != nil {
		t.Fatal(err)
	}
	if installed.Version != core.ApacheWAFVersion {
		t.Fatal("fixture must be the current actual application", installed.Version)
	}
	cfg, err := core.DecodeApacheWAFConfig(installed.Settings)
	if err != nil || cfg.Policy.Revision < 1 {
		t.Fatal("current installed configuration cannot form a lost-ack replay", err)
	}
	before := apacheReplayReadTriplet(t, s)
	cfg.Policy.Revision--
	raw := core.WAFSettings(cfg)
	if match, err := s.confirmApacheWAFReplay(context.Background(), raw); !match || err != nil {
		t.Fatal("actual loaded replay was not confirmed", match, err)
	}
	// Old clients may omit the identity policy, but cannot erase it by retrying.
	delete(raw, "trusted_proxy")
	if match, err := s.confirmApacheWAFReplay(context.Background(), raw); !match || err != nil {
		t.Fatal("omitted identity policy replay was not preserved", match, err)
	}
	apacheReplayRequireSameTriplet(t, s, before)
}

func TestApacheWAFReplayFilesAloneCannotClaimLiveProtection(t *testing.T) {
	live := requireApacheReplayInstalled(t)
	var installed struct {
		Settings map[string]any `json:"settings"`
	}
	if err := moduleRead(filepath.Join(live.moduleDir("apache-waf"), "installed.json"), &installed); err != nil {
		t.Fatal(err)
	}
	current, err := core.DecodeApacheWAFConfig(installed.Settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"stale-loaded-fingerprint", "missing-host-mount", "duplicate-host-mount", "missing-site-identity", "pending-transaction"} {
		t.Run(kind, func(t *testing.T) {
			s := wafPolicyFixture(t)
			s.Config.ApacheSiteConfig = filepath.Join(s.Config.SystemRoot, "apache", "httpd.conf")
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				t.Fatal("failed replay tried to reload or repair the daemon")
				return "", nil
			}
			cfg := core.DefaultApacheWAFConfig()
			cfg.Policy.Revision = current.Policy.Revision + 10
			id := strings.Repeat("a", 32)
			source := "# managed by panel\n<VirtualHost 127.0.0.1:19080>\n ServerName qa-replay-only.localhost\n SetEnvIfExpr \"true\" PANEL_AW_SITE=" + id + "\n " + apacheWAFInclude + " CustomLog /var/log/apache2/panel-" + id + ".access.log combined\n</VirtualHost>\n"
			if kind == "missing-host-mount" {
				source = strings.Replace(source, " "+apacheWAFInclude, "", 1)
			}
			if kind == "duplicate-host-mount" {
				source = strings.Replace(source, " "+apacheWAFInclude, " "+apacheWAFInclude+" "+apacheWAFInclude, 1)
			}
			if kind == "missing-site-identity" {
				source = strings.Replace(source, " SetEnvIfExpr \"true\" PANEL_AW_SITE="+id+"\n", "", 1)
			}
			bindings, err := apacheWAFBindings(source)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := renderApacheWAF(cfg, bindings)
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{filepath.Dir(s.Config.ApacheSiteConfig), s.moduleDir("apache-waf")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(s.Config.ApacheSiteConfig, []byte(source), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.moduleDir("apache-waf"), "rules.conf"), []byte(rules), 0644); err != nil {
				t.Fatal(err)
			}
			if err := moduleWrite(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(cfg)}); err != nil {
				t.Fatal(err)
			}
			if kind == "pending-transaction" {
				path := s.apacheWAFTransactionService().wafPendingPath()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("retained-unconfirmed-evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := apacheReplayReadTriplet(t, s)
			cfg.Policy.Revision--
			raw := core.WAFSettings(cfg)
			if !s.apacheWAFReplay(raw) {
				t.Fatal("fixture did not reproduce the former file-only acceptance")
			}
			match, err := s.confirmApacheWAFReplay(context.Background(), raw)
			if !match || err == nil || !strings.Contains(err.Error(), "未重新写入或重载") {
				t.Fatal("file-only replay claimed protection or lost its refusal", match, err)
			}
			if kind == "stale-loaded-fingerprint" && !strings.Contains(err.Error(), "实际加载指纹") {
				t.Fatal("test failed before the real live-fingerprint boundary", err)
			}
			apacheReplayRequireSameTriplet(t, s, before)
			if _, err := os.Lstat(filepath.Join(s.moduleDir("apache-waf"), "config-backups")); !os.IsNotExist(err) {
				t.Fatal("refused replay began a backup or mutation", err)
			}
		})
	}
}

func apacheReplayReadTriplet(t *testing.T, s *Service) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, path := range s.apacheWAFConfigurationPaths() {
		data, err := apacheWAFReadStableFile(path, 2<<20)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = data
	}
	return result
}

func apacheReplayRequireSameTriplet(t *testing.T, s *Service, before map[string][]byte) {
	t.Helper()
	for path, data := range apacheReplayReadTriplet(t, s) {
		if !bytes.Equal(before[path], data) {
			t.Fatal("replay changed original bytes", path)
		}
	}
}
