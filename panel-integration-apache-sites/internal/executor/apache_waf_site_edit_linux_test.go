//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func apacheMetadataSiteFixtureSource() string {
	id := strings.Repeat("a", 32)
	return "# managed by panel\n<VirtualHost 127.0.0.1:19080>\n  ServerName fixture.example.test\n  SetEnvIfExpr \"true\" PANEL_AW_SITE=" + id + "\n  IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules.conf\n  CustomLog /var/log/apache2/panel-" + id + ".access.log combined\n</VirtualHost>\n"
}

func TestApacheMetadataSitePolicyRetainsVersionProxyAndLiteralRules(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 9
	cfg.Policy.Rules = []core.WAFRule{{ID: strings.Repeat("b", 32), Name: "fixture literal rule", Field: "uri", Operator: "contains", Value: "/private-archive", Action: "block", Enabled: true}}
	for _, version := range []string{core.ApacheWAFVersion, "2.2.0", "2.1.0", "2.0.0"} {
		source, rules, err := apacheMetadataSitePolicy(apacheMetadataSiteFixtureSource(), cfg, version, "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so")
		if err != nil || !strings.Contains(rules, apacheWAFProbeVersion(cfg, version)) || !strings.Contains(rules, apacheWAFLiteral("/private-archive")) || !strings.Contains(source, "PANEL_AW_SITE=") || strings.Contains(source, "security2_module") {
			t.Fatal("metadata policy or exact application version lost", version, err)
		}
		again, same, err := apacheMetadataSitePolicy(source, cfg, version, "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so")
		if err != nil || again != source || same != rules {
			t.Fatal("unchanged policy is not byte-idempotent", err)
		}
	}
	cfg.TrustedProxy = &core.WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"127.0.0.1/32"}, AcknowledgeHeaderControl: true}
	source, rules, err := apacheMetadataSitePolicy(apacheMetadataSiteFixtureSource(), cfg, core.ApacheWAFVersion, "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so")
	if err != nil || !strings.Contains(source, "LoadModule remoteip_module") || !strings.Contains(rules, "RemoteIPHeader X-Forwarded-For") || !strings.Contains(rules, "127.0.0.1/32") {
		t.Fatal("saved proxy policy was lost", err)
	}
	cfg.TrustedProxy.AcknowledgeHeaderControl = false
	if _, _, err := apacheMetadataSitePolicy(apacheMetadataSiteFixtureSource(), cfg, core.ApacheWAFVersion, "/module.so"); err == nil {
		t.Fatal("unacknowledged proxy trust was silently enabled")
	}
}

func TestApacheMetadataSitePolicyRefusesCapabilityPromotionAndForeignSource(t *testing.T) {
	base, cfg := apacheMetadataSiteFixtureSource(), core.DefaultApacheWAFConfig()
	for _, version := range []string{core.ApacheWAFNativeBodyVersion, "99.0.0", "", "2.3.0\n"} {
		if _, _, err := apacheMetadataSitePolicy(base, cfg, version, "/module.so"); err == nil {
			t.Fatal("website edit adopted another application capability", version)
		}
	}
	for _, content := range []string{base + "Include /tmp/foreign.conf\n", base + "LoadModule security2_module /tmp/foreign.so\n", "# unmanaged\n", base + base} {
		if _, _, err := apacheMetadataSitePolicy(content, cfg, core.ApacheWAFVersion, "/module.so"); err == nil {
			t.Fatal("foreign or ambiguous source was adopted")
		}
	}
	cfg.Body = &core.WAFBodyConfig{}
	if _, _, err := apacheMetadataSitePolicy(base, cfg, core.ApacheWAFVersion, "/module.so"); err == nil {
		t.Fatal("metadata application gained native request body policy")
	}
}

func TestApacheMetadataSiteBackupComparisonCannotNormalizeTamper(t *testing.T) {
	a := fileBackup{path: "/owned/config", existed: true, mode: 0644, owner: &fileOwner{UID: 0, GID: 0}, data: []byte("original bytes")}
	if !apacheMetadataSiteBackupSame(a, a) {
		t.Fatal("identical original snapshot refused")
	}
	for _, mutate := range []func(*fileBackup){func(z *fileBackup) { z.path += "-other" }, func(z *fileBackup) { z.existed = false }, func(z *fileBackup) { z.mode = 0600 }, func(z *fileBackup) { z.owner = nil }, func(z *fileBackup) { z.owner = &fileOwner{UID: 1, GID: 0} }, func(z *fileBackup) { z.data = []byte("replacement") }} {
		z := a
		mutate(&z)
		if apacheMetadataSiteBackupSame(a, z) {
			t.Fatal("a changed protected field was normalized away")
		}
	}
}

func TestApacheMetadataSiteRefusalHasNoCommandOrFileMutation(t *testing.T) {
	for _, scenario := range []string{"not-installed", "bad-identity", "native-version", "last-protected-site", "duplicate-manifest", "missing-rules"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			s := New(Config{SystemRoot: root, SitesDir: filepath.Join(root, "sites"), SecurityDir: filepath.Join(root, "security"), ApacheSiteConfig: filepath.Join(root, "apache", "httpd.conf"), Run: func(context.Context, string, ...string) (string, error) {
				t.Fatal("refusal invoked an external command")
				return "", nil
			}})
			txs := s.apacheWAFTransactionService()
			paths := txs.apacheWAFConfigurationPaths()
			for _, path := range paths {
				if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
					t.Fatal(err)
				}
			}
			before := []byte(apacheMetadataSiteFixtureSource())
			if err := os.WriteFile(paths[0], before, 0644); err != nil {
				t.Fatal(err)
			}
			if scenario != "not-installed" {
				document := `{"id":"apache-waf","version":"2.3.0","settings":{}}`
				if scenario == "bad-identity" {
					document = strings.Replace(document, "apache-waf", "nginx-waf", 1)
				}
				if scenario == "native-version" {
					document = strings.Replace(document, "2.3.0", "2.4.0", 1)
				}
				if scenario == "duplicate-manifest" {
					document = `{"id":"apache-waf","id":"apache-waf","version":"2.3.0","settings":{}}`
				}
				if err := os.WriteFile(paths[2], []byte(document), 0600); err != nil {
					t.Fatal(err)
				}
			}
			count := 1
			if scenario == "last-protected-site" {
				count = 0
			}
			undo, handled, err := s.applyApacheWAFMetadataSites(context.Background(), "candidate source", count, func(string) { t.Fatal("refusal reported an apply") })
			if undo != nil || scenario == "not-installed" && (handled || err != nil) || scenario != "not-installed" && (!handled || err == nil) {
				t.Fatal("wrong refusal boundary", handled, err)
			}
			after, err := os.ReadFile(paths[0])
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal modified original source", err)
			}
		})
	}
}
