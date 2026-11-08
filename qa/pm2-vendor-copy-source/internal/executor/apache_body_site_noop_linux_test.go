//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestApacheNativeBodySiteNoopPurePlanPreservesPolicyAndEngine(t *testing.T) {
	module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
	for _, mode := range []string{"block", "observe", "off"} {
		t.Run(mode, func(t *testing.T) {
			base, _, cfg := apacheBodyConfigFixture()
			cfg.Policy.Mode = mode
			cfg.Policy.Revision = 21
			before, _ := json.Marshal(core.WAFSettings(cfg))
			original, rules, err := apacheBodySitePolicy(base, cfg, module)
			if err != nil {
				t.Fatal(err)
			}
			prepared, sameRules, err := apacheBodySitePolicy(base, cfg, module)
			if err != nil || prepared != original || sameRules != rules {
				t.Fatal("unchanged native plan changed bytes", err)
			}
			same, err := apacheBodySiteSourceSame(prepared, original, cfg, module)
			if err != nil || !same {
				t.Fatal("exact native generation not recognized", err)
			}
			after, _ := json.Marshal(core.WAFSettings(cfg))
			if string(before) != string(after) || cfg.Policy.Revision != 21 || cfg.Body.EngineJobID != apacheBodyConfigEngine {
				t.Fatal("pure plan altered policy/engine/revision")
			}
		})
	}
}

func TestApacheNativeBodySiteNoopAllowsOnlyReviewedRemoteIPRelocation(t *testing.T) {
	base, _, cfg := apacheBodyConfigFixture()
	module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
	line := "LoadModule remoteip_module \"" + module + "\"\n"
	originalBase := strings.Replace(base, "# managed by panel\n", "# managed by panel\n"+line, 1)
	candidateBase := strings.Replace(base, "<VirtualHost", line+"<VirtualHost", 1)
	original, _, err := apacheBodySitePolicy(originalBase, cfg, module)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := apacheBodySitePolicy(candidateBase, cfg, module)
	if err != nil {
		t.Fatal(err)
	}
	same, err := apacheBodySiteSourceSame(candidate, original, cfg, module)
	if err != nil || !same {
		t.Fatal("exact global relocation rejected", err)
	}
	mutations := map[string]string{
		"host":             strings.Replace(candidate, "a.localhost", "other.localhost", 1),
		"document-root":    strings.Replace(candidate, "/public", "/other", 1),
		"outside-comment":  candidate + "# unrelated outside change\n",
		"body-mode":        strings.Replace(candidate, "SecRuleEngine On", "SecRuleEngine DetectionOnly", 1),
		"engine":           strings.ReplaceAll(candidate, apacheBodyConfigEngine, strings.Repeat("a", 32)),
		"duplicate-loader": candidate + line,
		"foreign-include":  candidate + "Include /tmp/foreign.conf\n",
		"body-relocation":  strings.Replace(candidate, apacheBodyGlobalBegin, apacheBodyGlobalBegin+"# unexpected policy\n", 1),
	}
	for name, source := range mutations {
		t.Run(name, func(t *testing.T) {
			same, err := apacheBodySiteSourceSame(source, original, cfg, module)
			if same {
				t.Fatal("non-relocation content accepted as no-op", err)
			}
		})
	}
}

func TestApacheNativeBodySiteNoopNeverPromotesForeignCandidate(t *testing.T) {
	base, _, cfg := apacheBodyConfigFixture()
	module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
	for _, bad := range []string{base + "Include /tmp/foreign.conf\n", base + "SecRuleEngine On\n", base + "LoadModule security2_module /foreign.so\n", strings.Replace(base, apacheBodyConfigSiteA, strings.Repeat("f", 32), -1)} {
		if _, _, err := apacheBodySitePolicy(bad, cfg, module); err == nil {
			t.Fatal("foreign native plan was rendered")
		}
	}
}

// Fixture-only installed metadata is NOT a sealed-engine or signed-app claim.
// Deliberately no usable native DSO/cache exists in this private root. A no-op
// must not try to load it; actual changes must still refuse missing authority.
func TestApacheNativeBodySiteNoopPrivateTripletPreservationAndChangeRefusal(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_NOOP") != "1" {
		t.Skip("explicit root private installed-Apache component fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root private fixture required")
	}
	if _, err := apacheRelease(); err != nil {
		t.Fatal("actual installed Apache executable required", err)
	}
	for _, scenario := range []string{"identical", "relocation", "changed-host", "changed-root", "tampered-old-body", "tampered-old-rules", "duplicate-manifest", "pending", "last-protected-site"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			s := New(Config{SystemRoot: root, SitesDir: filepath.Join(root, "sites"), ConfDir: filepath.Join(root, "conf"), StateDir: filepath.Join(root, "state"), SecurityDir: filepath.Join(root, "security"), ApacheSiteConfig: filepath.Join(root, "apache", "httpd.conf"), Run: func(context.Context, string, ...string) (string, error) {
				t.Fatal("no-op/refusal invoked an external command")
				return "", nil
			}})
			txs := s.apacheWAFTransactionService()
			paths := txs.apacheWAFConfigurationPaths()
			for _, path := range paths {
				if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
					t.Fatal(err)
				}
			}
			base, _, cfg := apacheBodyConfigFixture()
			cfg.Policy.Revision = 21
			module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
			line := "LoadModule remoteip_module \"" + module + "\"\n"
			if scenario == "relocation" {
				base = strings.Replace(base, "# managed by panel\n", "# managed by panel\n"+line, 1)
			}
			original, rules, err := apacheBodySitePolicy(base, cfg, module)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := json.Marshal(map[string]any{"id": "apache-waf", "version": core.ApacheWAFNativeBodyVersion, "settings": core.WAFSettings(cfg), "fixture_provenance": "not-a-sealed-engine-or-signed-installation"})
			if err != nil {
				t.Fatal(err)
			}
			candidate := base
			count := 2
			switch scenario {
			case "relocation":
				candidate = strings.Replace(strings.Replace(base, line, "", 1), "<VirtualHost", line+"<VirtualHost", 1)
			case "changed-host":
				candidate = strings.Replace(base, "a.localhost", "changed.localhost", 1)
			case "changed-root":
				candidate = strings.Replace(base, "/public", "/other", 1)
			case "tampered-old-body":
				original = strings.Replace(original, "SecRuleEngine On", "SecRuleEngine DetectionOnly", 1)
			case "tampered-old-rules":
				rules += "# external rule\n"
			case "duplicate-manifest":
				manifest = []byte(strings.Replace(string(manifest), "\"id\":\"apache-waf\"", "\"id\":\"apache-waf\",\"id\":\"apache-waf\"", 1))
			case "last-protected-site":
				count = 0
			}
			for i, raw := range [][]byte{[]byte(original), []byte(rules), manifest} {
				mode := os.FileMode(0640)
				if i == 2 {
					mode = 0600
				}
				if err := atomicWrite(paths[i], raw, mode); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "pending" {
				if err := txs.wafOwnedDirectory(filepath.Dir(txs.wafPendingPath()), true); err != nil {
					t.Fatal(err)
				}
				if err := atomicWrite(txs.wafPendingPath(), []byte("unverified original transaction\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := []fileBackup{}
			infos := []os.FileInfo{}
			for _, path := range paths {
				v, err := txs.apacheWAFStableBackup(path)
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, v)
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				infos = append(infos, info)
			}
			undo, handled, err := s.applyApacheNativeBodySites(context.Background(), candidate, count, func(string) {})
			noop := scenario == "identical" || scenario == "relocation"
			if !handled || noop && (err != nil || undo == nil) || !noop && (err == nil || undo != nil) {
				t.Fatal("wrong native no-op/change refusal", handled, err)
			}
			if noop && undo() != nil {
				t.Fatal("no-op compensation must not invoke services or write")
			}
			for i, path := range paths {
				after, err := txs.apacheWAFStableBackup(path)
				if err != nil || !reflect.DeepEqual(before[i], after) {
					t.Fatal("triplet bytes/modes/owners changed", path, err)
				}
				info, err := os.Lstat(path)
				if err != nil || !os.SameFile(infos[i], info) || infos[i].Mode() != info.Mode() || !infos[i].ModTime().Equal(info.ModTime()) {
					t.Fatal("no-op/refusal replaced file identity", path, err)
				}
			}
			if cfg.Policy.Revision != 21 {
				t.Fatal("unrelated site edit revised native policy")
			}
		})
	}
}
