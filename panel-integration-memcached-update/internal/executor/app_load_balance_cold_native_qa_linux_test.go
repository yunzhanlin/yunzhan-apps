//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Coordinator validates this exact PID/start, kills the owned companion,
// then performs a true VM stop/start. No active Nginx reload is performed here.
func TestLoadBalanceColdInterruptionPrepareNativeQA(t *testing.T) {
	qa := os.Getenv("PANEL_LB_COLD_QA_ID")
	if qa == "" {
		t.Skip("explicit private cold coordinator required")
	}
	host, e := os.ReadFile("/etc/hostname")
	if e != nil || os.Geteuid() != 0 || !core.ValidID(qa) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main/unknown host")
	}
	b, e := exec.Command("/usr/bin/sqlite3", "/var/lib/panel/panel.db", "SELECT (SELECT count(*) FROM jobs WHERE state IN ('queued','running'))+(SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running'));").Output()
	if e != nil || strings.TrimSpace(string(b)) != "0" {
		t.Fatal("other active work")
	}
	s := nativeWAFService()
	lock, e := s.lockWAFConfiguration()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	for _, p := range []string{s.loadBalancePendingPath(), s.wafPendingPath()} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("pre-existing pending state")
		}
	}
	if !s.moduleInstalled("load-balance") {
		t.Fatal("does not install absent app")
	}
	domain := "lb-cold-" + qa[:12] + ".example.test"
	conf, meta := s.loadBalancePaths(domain)
	for _, p := range []string{conf, meta} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("own target collision")
		}
	}
	next := loadBalanceEntry{Format: 1, Revision: 1, Domain: domain, Port: 41975, Nodes: []core.AppUpstream{{Address: "127.0.0.1:41003", Weight: 1}, {Address: "127.0.0.1:41004", Weight: 1}}}
	rendered, e := renderLoadBalanceEntry(next)
	if e != nil {
		t.Fatal(e)
	}
	metadata, _ := json.MarshalIndent(next, "", "  ")
	metadata = append(metadata, '\n')
	for _, dir := range []string{filepath.Dir(conf), filepath.Dir(meta), filepath.Dir(s.loadBalancePendingPath())} {
		if e = s.wafOwnedDirectory(dir, true); e != nil {
			t.Fatal(e)
		}
	}
	changes := []wafConfigChange{{Path: conf, NextData: []byte(rendered), NextExists: true, NextMode: 0644}, {Path: meta, NextData: metadata, NextExists: true, NextMode: 0600}}
	tx := loadBalanceTransaction{Format: 1, ID: core.ID(), Domain: domain, State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
	for _, c := range changes {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
		ok, e := s.wafCurrentMatches(c, false)
		if e != nil || !ok {
			t.Fatal("preparation conflict", e)
		}
	}
	if e = s.writeLoadBalanceTransaction(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), tx.ID+".json"), tx); e != nil {
		t.Fatal(e)
	}
	if e = s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
		t.Fatal(e)
	}
	if e = wafApplyChange(tx.Changes[0], true); e != nil {
		t.Fatal(e)
	}
	// Deliberately omit the metadata write and the native reload.
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	start, e := moduleProcessStart("/proc", os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join("/var/lib/panel-executor", "lb-cold-qa")
	if e = s.wafOwnedDirectory(dir, true); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = moduleWrite(filepath.Join(dir, qa+".json"), map[string]any{"qa_id": qa, "phase": "staged_waiting_for_SIGKILL", "passed": false, "source_candidate_only": true, "signed_release_acceptance": false, "transaction_id": tx.ID, "domain": domain, "configuration_path": conf, "metadata_path": meta, "boot_before": strings.TrimSpace(string(boot)), "master_not_reloaded": true, "metadata_not_committed": true, "preparation_process_pid": os.Getpid(), "preparation_process_start": start}); e != nil {
		t.Fatal(e)
	}
	for {
		time.Sleep(time.Second)
	}
}
