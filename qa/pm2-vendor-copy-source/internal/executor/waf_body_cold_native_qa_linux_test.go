//go:build linux

package executor

import (
	"context"
	"fmt"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Only the private QA coordinator may run this. It intentionally leaves a
// partially committed durable transaction and waits to be SIGKILLed. A cold
// boot then executes the real NginxCommand preflight in a fresh process.
func TestWAFBodyColdInterruptionPrepareNativeQA(t *testing.T) {
	engine, qa := os.Getenv("PANEL_WAF_COLD_QA_ENGINE"), os.Getenv("PANEL_WAF_COLD_QA_ID")
	if engine == "" && qa == "" {
		t.Skip("explicit disposable cold-fault coordinator required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(engine) || !core.ValidID(qa) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main/unknown/non-root cold test")
	}
	if output, err := exec.Command("/usr/bin/sqlite3", "/var/lib/panel/panel.db", "SELECT (SELECT count(*) FROM jobs WHERE state IN ('queued','running'))+(SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running'));").Output(); err != nil || strings.TrimSpace(string(output)) != "0" {
		t.Fatal("other active QA work")
	}
	if err := VerifyWAFEngineBuild(engine); err != nil {
		t.Fatal(err)
	}
	s := nativeWAFService()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		t.Fatal("existing pending WAF transaction; never replace")
	}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || previous.Body != nil || previous.Policy.Mode != "block" {
		t.Fatal("refuse to replace active native protection or global mode")
	}
	backup, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	site := core.ID()
	domain := "waf-cold-" + qa[:12] + ".localhost"
	path := filepath.Join(s.Config.ConfDir, site+".conf")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("own cold fixture collision")
	}
	fixture := fmt.Sprintf("# managed by panel; site=%s\nserver {\n  listen 127.0.0.1:19101;\n  server_name %s;\n  access_log off;\n  location / { return 200 'owned-waf-cold-recovery'; }\n}\n", site, domain)
	if err := atomicWrite(path, []byte(fixture), 0644); err != nil {
		t.Fatal(err)
	}
	current := previous
	policy := core.DefaultWAFBodyPolicy()
	policy.Mode = "block"
	current.Body = &core.WAFBodyConfig{EngineJobID: engine, Sites: []core.WAFBodySitePolicy{{SiteID: site, Policy: policy}}}
	if err := s.prepareWAFBodyTemporary(current); err != nil {
		t.Fatal(err)
	}
	plan, err := s.planWAFConfiguration(current, false)
	if err != nil || len(plan) < 6 {
		t.Fatal("incomplete actual native transaction", len(plan), err)
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	written := []string{}
	for _, change := range plan {
		if change.Path == s.softwareManifestPath("nginx-waf") {
			continue
		}
		if err := wafApplyChange(change, true); err != nil {
			t.Fatal(err)
		}
		written = append(written, change.Path)
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Config.Run(context.Background(), nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		t.Fatal("staged native configuration fails actual parser", err)
	}
	// Do not reload: the normal Nginx master still serves its original config.
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	proofDir := "/var/lib/panel-executor/waf-cold-qa"
	if err := s.wafOwnedDirectory(proofDir, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(proofDir, 0700); err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"qa_id": qa, "state": "staged_waiting_for_SIGKILL", "passed": false, "source_candidate_only": true, "signed_release_acceptance": false, "engine_job": engine, "transaction_id": tx.ID, "backup_directory": backup, "fixture_site_id": site, "fixture_domain": domain, "fixture_configuration_sha256": core.Hash(fixture), "fixture_configuration_path": path, "boot_before": strings.TrimSpace(string(boot)), "written_before_kill": written, "manifest_not_committed": true, "master_not_reloaded": true, "preparation_process_pid": os.Getpid()}
	if err := moduleWrite(filepath.Join(proofDir, qa+".json"), proof); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}
