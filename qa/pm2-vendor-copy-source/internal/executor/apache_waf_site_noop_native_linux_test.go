//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

// Only the explicit Linux component runner selects this test. The installed
// Apache executable is read, never replaced or executed. All policy fixtures
// belong to the test's declared private root. This is not a live-service or
// signed-application acceptance claim; the normal website API is tested later.
func TestApacheMetadataSiteNoopPreservesUnrelatedStoppedService(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_METADATA_NOOP") != "1" {
		t.Skip("explicit Linux installed-Apache private component fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("private root fixture required")
	}
	if _, err := apacheRelease(); err != nil {
		t.Fatal("actual installed Apache executable required", err)
	}
	for _, scenario := range []string{"identical", "exact-module-relocation", "changed-host-stopped", "changed-alias-stopped", "wrong-rules", "duplicate-manifest", "pending-transaction"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			calls := 0
			s := New(Config{SystemRoot: root, SitesDir: filepath.Join(root, "sites"), ConfDir: filepath.Join(root, "conf"), StateDir: filepath.Join(root, "state"), SecurityDir: filepath.Join(root, "security"), ApacheSiteConfig: filepath.Join(root, "apache", "httpd.conf"), Run: func(_ context.Context, name string, args ...string) (string, error) {
				calls++
				if (scenario == "changed-host-stopped" || scenario == "changed-alias-stopped") && name == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"is-active", "panel-apache"}) {
					return "inactive\n", errors.New("actual change must retain stopped-service refusal")
				}
				t.Fatalf("unchanged/refused plan invoked external command: %s %q", name, args)
				return "", nil
			}})
			txs := s.apacheWAFTransactionService()
			paths := txs.apacheWAFConfigurationPaths()
			for _, path := range paths {
				if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
					t.Fatal(err)
				}
			}
			cfg := core.DefaultApacheWAFConfig()
			cfg.Policy.Revision = 10
			module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
			base := apacheMetadataSiteFixtureSource()
			if scenario == "exact-module-relocation" {
				// Disabled proxy still permits the renderer's one exact owned
				// LoadModule relocation; neither file is rewritten on a no-op.
				base = strings.Replace(base, "# managed by panel\n", "# managed by panel\nLoadModule remoteip_module \""+module+"\"\n", 1)
			}
			source, rules, err := apacheMetadataSitePolicy(base, cfg, core.ApacheWAFVersion, module)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := json.Marshal(map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(cfg), "fixture_provenance": "component-only-not-signed-installation"})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong-rules" {
				rules += "# unexpected replacement\n"
			}
			if scenario == "duplicate-manifest" {
				manifest = []byte(strings.Replace(string(manifest), `"id":"apache-waf"`, `"id":"apache-waf","id":"apache-waf"`, 1))
			}
			for i, data := range [][]byte{[]byte(source), []byte(rules), manifest} {
				mode := os.FileMode(0640)
				if i == 2 {
					mode = 0600
				}
				if err := atomicWrite(paths[i], data, mode); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "pending-transaction" {
				if err := txs.wafOwnedDirectory(filepath.Dir(txs.wafPendingPath()), true); err != nil {
					t.Fatal(err)
				}
				if err := atomicWrite(txs.wafPendingPath(), []byte("retained unknown transaction\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := []fileBackup{}
			for _, path := range paths {
				v, err := txs.apacheWAFStableBackup(path)
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, v)
			}
			candidate := source
			switch scenario {
			case "exact-module-relocation":
				line := "LoadModule remoteip_module \"" + module + "\"\n"
				candidate = strings.Replace(strings.Replace(source, line, "", 1), "<VirtualHost", line+"<VirtualHost", 1)
			case "changed-host-stopped":
				candidate = strings.Replace(source, "fixture.example.test", "changed.example.test", 1)
			case "changed-alias-stopped":
				candidate = strings.Replace(source, "</VirtualHost>", "  ServerAlias changed.example.test\n</VirtualHost>", 1)
			}
			undo, handled, err := s.applyApacheWAFMetadataSites(context.Background(), candidate, 1, func(string) {})
			noop := scenario == "identical" || scenario == "exact-module-relocation"
			if !handled || noop && (err != nil || undo == nil) || !noop && (err == nil || undo != nil) {
				t.Fatal("wrong unchanged/change refusal boundary", handled, err)
			}
			if noop && undo() != nil {
				t.Fatal("no-op compensation must not write or invoke services")
			}
			wantCalls := 0
			if strings.HasSuffix(scenario, "-stopped") {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("unexpected external command count", calls, wantCalls)
			}
			for i, path := range paths {
				after, err := txs.apacheWAFStableBackup(path)
				if err != nil || !reflect.DeepEqual(before[i], after) {
					t.Fatal("complete triplet bytes, existence, modes or owners changed", path, err)
				}
			}
		})
	}
}
