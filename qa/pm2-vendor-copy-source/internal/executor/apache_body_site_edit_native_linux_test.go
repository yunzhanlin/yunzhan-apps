//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// A component policy fixture is not an app installation or signed receipt.
// An outer runner creates a distinct, genuine Apache systemd unit and maps
// only the closed panel-apache command names to that owned unit. Config.Run
// remains the actual external command implementation, with no result double.
func TestApacheBodySiteEditNativeTransactionsAndCompensation(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_SITE_TRANSACTION") != "1" {
		t.Skip("explicit owned native service transaction fixture required")
	}
	job := os.Getenv("PANEL_QA_APACHE_BODY_ENGINE")
	if os.Geteuid() != 0 || !core.ValidID(job) {
		t.Fatal("restricted root and genuine sealed authority required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	if err := verifyApacheBodyBuildContext(ctx, job); err != nil {
		t.Fatal(err)
	}
	sealed, err := readApacheBodyBuildRecord(job)
	if err != nil {
		t.Fatal(err)
	}
	fixture := "/run/panel-apache-body-sites24ahh"
	if err := apacheBodyOwnedAncestors(fixture); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", StateDir: "/var/lib/panel-executor", ConfDir: "/etc/nginx/panel-sites"})
	txs := s.apacheWAFTransactionService()
	sites := []core.Site{
		{ID: apacheBodyConfigSiteA, Domain: "protected-a.localhost", Status: "running", Settings: core.SiteSettings{WebServer: "apache"}},
		{ID: apacheBodyConfigSiteB, Domain: "protected-b.localhost", Status: "running", Settings: core.SiteSettings{WebServer: "apache"}},
	}
	for _, site := range sites {
		base := filepath.Join(s.Config.SitesDir, site.ID)
		public := filepath.Join(base, "public")
		if err := os.MkdirAll(public, 0755); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{base, public} {
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(public, "index.html")
		if err := os.WriteFile(path, []byte("owned-site:"+site.ID+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	render := func(sites []core.Site) string {
		t.Helper()
		source, count, err := renderApacheSites(sites, s.Config.SitesDir)
		if err != nil || count != 2 {
			t.Fatal("real website renderer", err, count)
		}
		// Bound this fixture's old/new generations inside its private unit.
		// These limits are not claimed as production hardware sizing evidence.
		limits := fmt.Sprintf("DefaultRuntimeDir %s\nStartServers 1\nServerLimit 2\nThreadsPerChild 8\nMaxRequestWorkers 16\nMinSpareThreads 1\nMaxSpareThreads 16\n", fixture)
		return strings.Replace(source, "TypesConfig /etc/mime.types\n", limits+"TypesConfig /etc/mime.types\n", 1)
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 10
	cfg.Body = &core.WAFBodyConfig{EngineJobID: job, Sites: []core.WAFBodySitePolicy{}}
	for i, site := range sites {
		p := core.DefaultWAFBodyPolicy()
		p.Mode = "block"
		if i == 1 {
			p.Mode = "observe"
		}
		cfg.Body.Sites = append(cfg.Body.Sites, core.WAFBodySitePolicy{SiteID: site.ID, Policy: p})
	}
	base := render(sites)
	// Leave the actual bounded mount empty for the fixed cold startup CLI.
	source, err := transitionApacheBodySource(base, core.DefaultApacheWAFConfig(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := apacheWAFBindings(source)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := renderApacheWAFVersion(cfg, bindings, core.ApacheWAFNativeBodyVersion)
	if err != nil {
		t.Fatal(err)
	}
	paths := txs.apacheWAFConfigurationPaths()
	for i, data := range []string{source, rules} {
		mode := os.FileMode(0644)
		if i == 0 {
			mode = 0640
		}
		if err := atomicWrite(paths[i], []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	provenance := map[string]any{"component_fixture_only": true, "signed_application_receipt": false, "origin_engine_job": job}
	if err := moduleWrite(paths[2], map[string]any{"id": "apache-waf", "version": core.ApacheWAFNativeBodyVersion, "installed_at": "2026-10-11T00:00:00Z", "settings": core.WAFSettings(cfg), "fixture_provenance": provenance}); err != nil {
		t.Fatal(err)
	}
	startupProgram := os.Getenv("PANEL_QA_APACHE_BODY_COLD_BINARY")
	if startupProgram != "/run/panel-apache-body-sites24ahh/panel-executor-cold" {
		t.Fatal("fixed actual source-matched cold startup binary required")
	}
	if entries, err := os.ReadDir(apacheBodyTemporary); err != nil || len(entries) != 0 {
		t.Fatal("cold cache must initially be actually empty", err)
	}
	startupBackups := []fileBackup{}
	for _, path := range paths {
		b, err := txs.apacheWAFStableBackup(path)
		if err != nil {
			t.Fatal(err)
		}
		startupBackups = append(startupBackups, b)
	}
	for _, reject := range []string{"duplicate-nested", "upper-identity", "unknown-version", "old-with-body", "foreign-include", "broken-native-block"} {
		for _, before := range startupBackups {
			if err := atomicWrite(before.path, before.data, before.mode); err != nil {
				t.Fatal(err)
			}
		}
		path, data, mode := paths[2], startupBackups[2].data, startupBackups[2].mode
		switch reject {
		case "duplicate-nested":
			data = []byte(strings.Replace(string(data), `"fixture_provenance": {`, `"fixture_provenance": {"collision":"one","Collision":"two",`, 1))
		case "upper-identity":
			data = []byte(strings.Replace(string(data), `"id": "apache-waf"`, `"ID": "apache-waf"`, 1))
		case "unknown-version":
			data = []byte(strings.Replace(string(data), `"version": "2.4.0"`, `"version": "2.4.1"`, 1))
		case "old-with-body":
			data = []byte(strings.Replace(string(data), `"version": "2.4.0"`, `"version": "2.3.0"`, 1))
		case "foreign-include":
			path, mode, data = paths[0], startupBackups[0].mode, []byte(source+"Include /tmp/foreign.conf\n")
		case "broken-native-block":
			path, mode, data = paths[0], startupBackups[0].mode, []byte(strings.Replace(source, "SecRuleEngine On", "SecRuleEngine DetectionOnly", 1))
		}
		if err := atomicWrite(path, data, mode); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(ctx, startupProgram, "--prepare-apache-body-runtime").CombinedOutput()
		if err == nil {
			t.Fatal("actual cold startup accepted invalid authority", reject, string(output))
		}
		if entries, err := os.ReadDir(apacheBodyTemporary); err != nil || len(entries) != 0 {
			t.Fatal("invalid cold startup created cache leaves", reject, err)
		}
	}
	for _, before := range startupBackups {
		if err := atomicWrite(before.path, before.data, before.mode); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.CommandContext(ctx, startupProgram, "--prepare-apache-body-runtime").CombinedOutput(); err != nil {
		t.Fatal("actual cold startup on a committed two-site policy", err, string(output))
	}
	coldIdentity := map[string]uint64{}
	for _, site := range sites {
		st, err := os.Stat(filepath.Join(apacheBodyTemporary, site.ID))
		if err != nil || st.Mode() != os.ModeDir|0700 {
			t.Fatal("actual cold site cache missing or wrong mode", err)
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 33 || owner.Gid != 33 {
			t.Fatal("cold site cache does not belong to fixed www-data")
		}
		coldIdentity[site.ID] = owner.Ino
	}
	if output, err := exec.CommandContext(ctx, startupProgram, "--prepare-apache-body-runtime").CombinedOutput(); err != nil {
		t.Fatal("idempotent actual cold startup", err, string(output))
	}
	for _, site := range sites {
		st, err := os.Stat(filepath.Join(apacheBodyTemporary, site.ID))
		if err != nil || st.Sys().(*syscall.Stat_t).Ino != coldIdentity[site.ID] {
			t.Fatal("startup replaced an existing cache leaf")
		}
	}
	for _, before := range startupBackups {
		after, err := txs.apacheWAFStableBackup(before.path)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("startup rewrote installed configuration or receipt", err)
		}
	}
	if _, err := s.Config.Run(ctx, sealed.ApacheBinary, "-t", "-f", paths[0]); err != nil {
		t.Fatal("actual native initial parser", err)
	}
	if err := moduleWrite(filepath.Join(fixture, "service-ready.json"), map[string]any{"engine_job": job, "component_fixture_only": true}); err != nil {
		t.Fatal(err)
	}
	// The orchestrator starts its own actual service after the files exist.
	for deadline := time.Now().Add(25 * time.Second); ; {
		if err := apacheWAFWaitLoadedVersion(ctx, cfg, sites[0].Domain, core.ApacheWAFNativeBodyVersion); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("owned real Apache service not ready", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	unlock, err := s.lockApacheWAFSiteMutation()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	snapshot := func() []fileBackup {
		t.Helper()
		var result []fileBackup
		for _, path := range paths {
			b, err := txs.apacheWAFStableBackup(path)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, b)
		}
		return result
	}
	assertSnapshot := func(expected []fileBackup) {
		t.Helper()
		if now := snapshot(); !reflect.DeepEqual(expected, now) {
			t.Fatal("three-file bytes/existence/modes/owners were not restored")
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	var business []map[string]any
	check := func(policy core.WAFConfig) {
		t.Helper()
		for i, site := range sites {
			for _, attack := range []bool{false, true} {
				payload := `{"term":"ordinary"}`
				if attack {
					payload = `{"term":"<script>alert('owned-site-transaction')</script>"}`
				}
				req, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:19080/index.html", strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = site.Domain
				req.Header.Set("Content-Type", "application/json")
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := io.ReadAll(io.LimitReader(res.Body, 8192))
				res.Body.Close()
				wanted := 200
				if i == 0 && attack {
					wanted = 403
				}
				if readErr != nil || res.StatusCode != wanted || res.Header.Get("X-Panel-Apache-WAF") != apacheWAFProbeVersion(policy, core.ApacheWAFNativeBodyVersion) || wanted == 200 && string(data) != "owned-site:"+site.ID+"\n" {
					t.Fatal("real independent site policy/business after transaction", site.Domain, attack, wanted, res.StatusCode, string(data), readErr)
				}
				business = append(business, map[string]any{"host": site.Domain, "attack": attack, "status": res.StatusCode, "revision": policy.Policy.Revision})
			}
		}
	}
	check(cfg)
	original := snapshot()
	sites[0].Settings.Domains = []string{"owned-alias.localhost"}
	nextSource := render(sites)
	rollback, handled, err := s.applyApacheNativeBodySites(ctx, nextSource, 2, func(string) {})
	if err != nil || !handled || rollback == nil {
		t.Fatal("actual service website transaction", handled, err)
	}
	next := cfg
	next.Policy.Revision++
	check(next)
	manifest, err := apacheWAFReadStableFile(paths[2], 512<<10)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(manifest, &document); err != nil {
		t.Fatal(err)
	}
	var kept map[string]any
	if err := json.Unmarshal(document["fixture_provenance"], &kept); err != nil || !reflect.DeepEqual(kept, provenance) {
		t.Fatal("site edit discarded fixture provenance", err)
	}
	if err := rollback(); err != nil {
		t.Fatal("actual service compensation", err)
	}
	assertSnapshot(original)
	check(cfg)
	// Invalid outside directives reach the actual Apache parser. Native failed
	// apply must restore all three files and confirm the old loaded generation.
	undo, handled, err := s.applyApacheNativeBodySites(ctx, nextSource+"PanelOwnedInvalidDirective On\n", 2, func(string) {})
	if err == nil || !handled || undo != nil {
		t.Fatal("real native syntax failure was acknowledged", handled, err)
	}
	assertSnapshot(original)
	if _, err := os.Lstat(txs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native validated rollback left unresolved pending evidence", err)
	}
	check(cfg)
	// An external edit during compensation is not permission to overwrite it,
	// even when the other two paths still match the transaction's new state.
	rollback, handled, err = s.applyApacheNativeBodySites(ctx, nextSource, 2, func(string) {})
	if err != nil || !handled || rollback == nil {
		t.Fatal(err)
	}
	if err := atomicWrite(paths[1], append(snapshot()[1].data, []byte("# retained external edit\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	foreign := snapshot()
	trace := filepath.Join(fixture, "systemctl-calls.jsonl")
	commands, err := apacheWAFReadStableFile(trace, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if err := rollback(); err == nil {
		t.Fatal("compensation overwrote a foreign modification")
	}
	assertSnapshot(foreign)
	afterCommands, err := apacheWAFReadStableFile(trace, 64<<10)
	if err != nil || string(commands) != string(afterCommands) {
		t.Fatal("foreign refusal reloaded the real service", err)
	}
	if current, err := readApacheBodyBuildRecord(job); err != nil || !reflect.DeepEqual(current, sealed) {
		t.Fatal("site operation rewrote sealed engine authority", err)
	}
	if err := verifyApacheBodyBuildContext(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := moduleWrite(filepath.Join(fixture, "transaction-proof.json"), map[string]any{"passed": !t.Failed(), "source_component_fixture_only": true, "published_application_activation": false, "signed_application_receipt": false, "main_19100_started": false, "real_systemd_reload": true, "config_command_result_double": false, "three_file_compensation_exact": true, "real_native_parser_failure_restored": true, "foreign_compensation_preserved_without_reload": true, "installation_extension_fields_preserved": true, "sealed_engine_preserved": true, "actual_business_http": business, "actual_fixed_cli_cold_cache_initialized": true, "cold_start_six_invalid_authorities_refused": true, "cold_start_no_configuration_or_receipt_mutation": true, "cold_cache_leaf_inodes_preserved_on_recheck": coldIdentity, "actual_cache_hard_bytes": apacheBodyCacheBytes, "actual_cache_hard_inodes": apacheBodyCacheInodes}); err != nil {
		t.Fatal(err)
	}
}
