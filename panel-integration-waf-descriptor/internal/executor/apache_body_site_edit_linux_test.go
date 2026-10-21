//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestApacheBodyNativeExactConfigurationAllowsOnlySealedIncludes(t *testing.T) {
	base, off, native := apacheBodyConfigFixture()
	source, err := transitionApacheBodySource(base, off, native)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := apacheWAFBindings(source)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := renderApacheWAFVersion(native, bindings, core.ApacheWAFNativeBodyVersion)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	if domain, err := apacheWAFConfigurationFilesMatchVersion(source, native, "/missing/module.so", path, core.ApacheWAFNativeBodyVersion); err != nil || domain != "a.localhost" {
		t.Fatal("canonical sealed body includes falsely rejected", domain, err)
	}
	for _, bad := range []string{source + "Include /tmp/foreign.conf\n", strings.Replace(source, "SecRuleEngine On", "SecRuleEngine DetectionOnly", 1), source + "RemoteIPHeader X-Forwarded-For\n"} {
		if _, err := apacheWAFConfigurationFilesMatchVersion(bad, native, "/missing/module.so", path, core.ApacheWAFNativeBodyVersion); err == nil {
			t.Fatal("foreign body/proxy scope was permitted")
		}
	}
	if _, err := apacheWAFConfigurationFilesMatchVersion(source, native, "/missing/module.so", path, core.ApacheWAFVersion); err == nil {
		t.Fatal("old application silently acquired native capability")
	}
}

func TestApacheBodySiteManifestPreservesUnrelatedReceiptFields(t *testing.T) {
	before := []byte(`{"id":"apache-waf","version":"2.4.0","installed_at":"2026-10-11T00:00:00Z","future_receipt":{"sha":"opaque-value","nested":[1,true]},"settings":{},"updated_at":"old"}`)
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 19
	document, err := apacheBodySiteManifest(before, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(before, &old); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "version", "installed_at", "future_receipt"} {
		if string(document[key]) != string(old[key]) {
			t.Fatal("website edit discarded installation provenance", key)
		}
	}
	var raw map[string]any
	if err := json.Unmarshal(document["settings"], &raw); err != nil {
		t.Fatal(err)
	}
	decoded, err := core.DecodeApacheWAFNativeBodyConfig(raw)
	if err != nil || decoded.Policy.Revision != 19 || string(document["updated_at"]) == string(old["updated_at"]) {
		t.Fatal("website edit failed policy revision", err)
	}
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(`{"id":`), []byte(`{"id":"apache-waf","id":"nginx-waf"}`), []byte(`{"settings":{},"settings":null}`), []byte(`{} {}`), []byte(`{} true`), []byte(`{"ID":"apache-waf","version":"2.4.0","settings":{}}`), []byte(`{"id":"apache-waf","version":"2.4.0","settings":{"body":{"enabled":true,"Enabled":false}}}`), []byte(`{"id":"apache-waf","version":"2.4.0","settings":{},"receipt":{"a":[{"sha":"one","sha":"two"}]}}`), []byte(strings.Repeat(" ", (512<<10)+1))} {
		if _, err := apacheBodySiteManifest(bad, cfg); err == nil {
			t.Fatal("non-object installation was rewritten")
		}
	}
	deep := []byte(`{"id":"apache-waf","version":"2.4.0","settings":{},"receipt":` + strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17) + "}")
	if _, err := apacheBodySiteManifest(deep, cfg); err == nil {
		t.Fatal("unbounded receipt depth accepted")
	}
}

func TestApacheBodySiteEditsNoImplicitCapabilityOrOrphanErasure(t *testing.T) {
	for _, scenario := range []string{"never-installed", "orphan-native", "orphan-dso", "metadata-only", "metadata-orphan-native", "metadata-orphan-dso", "unknown-native", "unknown-metadata", "bad-identity", "damaged-manifest", "duplicate-manifest"} {
		t.Run(scenario, func(t *testing.T) {
			s := wafPolicyFixture(t)
			s.Config.ApacheSiteConfig = filepath.Join(s.Config.SystemRoot, "apache", "httpd.conf")
			txs := s.apacheWAFTransactionService()
			paths := txs.apacheWAFConfigurationPaths()
			for _, path := range paths {
				if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
					t.Fatal(err)
				}
			}
			base, _, native := apacheBodyConfigFixture()
			if scenario == "orphan-native" || scenario == "metadata-orphan-native" {
				base += apacheBodyGlobalBegin
			} else if scenario == "metadata-orphan-dso" || scenario == "orphan-dso" {
				base += "LoadModule security2_module /foreign/mod_security2.so\n"
			}
			if err := os.WriteFile(paths[0], []byte(base), 0644); err != nil {
				t.Fatal(err)
			}
			if scenario != "never-installed" && scenario != "orphan-native" && scenario != "orphan-dso" {
				id, version, cfg := "apache-waf", core.ApacheWAFVersion, core.DefaultApacheWAFConfig()
				if scenario == "unknown-native" {
					version, cfg = "99.0.0", native
				} else if scenario == "unknown-metadata" {
					version = "99.0.0"
				} else if scenario == "bad-identity" {
					id = "nginx-waf"
				}
				if err := moduleWrite(paths[2], map[string]any{"id": id, "version": version, "settings": core.WAFSettings(cfg)}); err != nil {
					t.Fatal(err)
				}
				if scenario == "damaged-manifest" {
					if err := os.WriteFile(paths[2], []byte(`{"id":`), 0600); err != nil {
						t.Fatal(err)
					}
				} else if scenario == "duplicate-manifest" {
					if err := os.WriteFile(paths[2], []byte(`{"id":"apache-waf","id":"apache-waf","version":"2.3.0","settings":{}}`), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				t.Fatal("read/refusal path executed an external command")
				return "", nil
			}
			undo, handled, err := s.applyApacheNativeBodySites(context.Background(), "new content", 2, func(string) { t.Fatal("refusal claimed a write") })
			ordinary := scenario == "never-installed" || scenario == "metadata-only"
			if ordinary && (handled || err != nil) || !ordinary && (!handled || err == nil) || undo != nil {
				t.Fatal("wrong native capability boundary", scenario, handled, err)
			}
			after, e := os.ReadFile(paths[0])
			if e != nil || string(before) != string(after) {
				t.Fatal("an unverified installation/orphan was overwritten", e)
			}
		})
	}
}

func TestApacheBodySiteEditPendingAbsenceIsNotUnknown(t *testing.T) {
	s := wafPolicyFixture(t)
	txs := s.apacheWAFTransactionService()
	path := txs.wafPendingPath()
	if err := s.apacheNativeBodyNoPending(); err != nil {
		t.Fatal(err)
	}
	if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("malformed evidence\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.apacheNativeBodyNoPending(); err == nil {
		t.Fatal("malformed evidence treated as no transaction")
	}
	retained := filepath.Join(filepath.Dir(path), "retained-pending.json")
	if err := os.Rename(path, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(path), strings.Repeat("f", 32)), path); err != nil {
		t.Fatal(err)
	}
	if err := s.apacheNativeBodyNoPending(); err == nil {
		t.Fatal("broken symlink evidence treated as absence")
	}
}
