//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var wafRetentionColdCuts = []string{"retention-intent-durable", "remove-intent-durable", "snapshot-unlink-durable", "retention-snapshot-removed", "retention-progress-durable"}

func TestWAFBodyRetentionColdQA(t *testing.T) {
	id, cut, phase := os.Getenv("PANEL_WAF_RETENTION_COLD_QA_ID"), os.Getenv("PANEL_WAF_RETENTION_COLD_QA_CUT"), os.Getenv("PANEL_WAF_RETENTION_COLD_QA_PHASE")
	if id == "" && cut == "" && phase == "" {
		t.Skip("explicit private retention SIGKILL/cold coordinator required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main/foreign/non-root cold QA")
	}
	valid := false
	for _, v := range wafRetentionColdCuts {
		valid = valid || v == cut
	}
	if !valid || (phase != "prepare" && phase != "verify") {
		t.Fatal("unknown retention cold case")
	}
	caseDir := filepath.Join("/var/lib/panel-executor/waf-retention-cold-qa", id, cut)
	if err := ownedRuntimePath(caseDir, true); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(caseDir, "filesystem")
	if phase == "prepare" {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := ownedRuntimePath(root, true); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), ConfDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("private metadata QA must not execute native commands")
		return "", nil
	}})
	ctx := context.Background()
	path := s.systemPath(wafBodyLogPath)
	row := []byte("2026/10/08 01:00:00 [warn] 321#321: yunzhan_waf_body rule=941100 phase=2 severity=2 disruptive=1 site=" + strings.Repeat("b", 32) + "\n")
	proofPath := filepath.Join(caseDir, "prepared.json")
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	cfg := wafRotationTestConfig()
	cfg.BodyLogRotation = nil
	cfg.BodyLogRetention = &core.WAFBodyLogRetentionConfig{Enabled: true, ConfirmDelete: true, Days: 30, KeepLatest: 1}
	if phase == "prepare" {
		if _, err := os.Lstat(proofPath); !os.IsNotExist(err) {
			t.Fatal("prior cold receipt exists")
		}
		if err := os.Mkdir(s.Config.SecurityDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := s.prepareWAFBodyLog(); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		for i := 0; i < 3; i++ {
			if err := os.WriteFile(path, row, 0640); err != nil {
				t.Fatal(err)
			}
			entry, err := s.snapshotAndTruncateWAFBodyLog(ctx)
			if err != nil {
				t.Fatal(err)
			}
			entry.CapturedAt = now.Add(-time.Duration(40-i) * 24 * time.Hour).Format(time.RFC3339)
			if err := s.writeWAFBodyLogIndex(ctx, entry); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, row, 0640); err != nil {
			t.Fatal(err)
		}
		lock, err := s.lockWAFConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		_, err = s.runWAFBodyRetentionLocked(ctx, now, lock, cfg, func(stage string) error {
			if stage != cut {
				return nil
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			record, sha, err := s.readWAFBodyRetentionRecord()
			if err != nil {
				t.Fatal(err)
			}
			if err := moduleWrite(proofPath, map[string]any{"id": id, "cut": cut, "pid": os.Getpid(), "boot_before": strings.TrimSpace(string(boot)), "current_sha256": core.Hash(string(row)), "current_inode": st.Sys().(*syscall.Stat_t).Ino, "record_sha256": sha, "record": record, "state": "waiting_for_SIGKILL", "metadata_fixture_only": true, "signed_release_acceptance": false}); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Second)
			}
		})
		t.Fatal("checkpoint not reached", err)
	}
	data, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		ID        string                 `json:"id"`
		Cut       string                 `json:"cut"`
		Boot      string                 `json:"boot_before"`
		SHA       string                 `json:"current_sha256"`
		Inode     uint64                 `json:"current_inode"`
		RecordSHA string                 `json:"record_sha256"`
		Record    wafBodyRetentionRecord `json:"record"`
		State     string                 `json:"state"`
	}
	if json.Unmarshal(data, &proof) != nil || proof.ID != id || proof.Cut != cut || proof.State != "waiting_for_SIGKILL" || proof.Boot == strings.TrimSpace(string(boot)) || proof.Record.Operation == nil {
		t.Fatal("no distinct actual cold boot")
	}
	verified := filepath.Join(caseDir, "verified.json")
	if _, err := os.Lstat(verified); !os.IsNotExist(err) {
		t.Fatal("prior verification exists")
	}
	live, err := os.ReadFile(path)
	st, statErr := os.Stat(path)
	if err != nil || statErr != nil || !bytes.Equal(live, row) || core.Hash(string(live)) != proof.SHA || st.Sys().(*syscall.Stat_t).Ino != proof.Inode {
		t.Fatal("cold changed current log bytes/inode")
	}
	record, sha, err := s.readWAFBodyRetentionRecord()
	if err != nil || sha != proof.RecordSHA || record.Operation == nil || record.Operation.State != "deleting" || record.Operation.PlanSHA256 != proof.Record.Operation.PlanSHA256 {
		t.Fatal("cold lost durable unknown deletion plan", record, err)
	}
	before, _ := os.ReadFile(s.wafBodyRetentionPath())
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	_, runErr := s.runWAFBodyRetentionLocked(ctx, time.Now().UTC(), lock, cfg, func(string) error { t.Fatal("cold automatically retried deletion"); return nil })
	lock.Close()
	after, _ := os.ReadFile(s.wafBodyRetentionPath())
	if runErr == nil || !bytes.Equal(before, after) {
		t.Fatal("unknown cold plan replayed or changed")
	}
	retained, err := s.retainWAFBodyRetentionOutcome(ctx, sha, time.Now().UTC())
	if err != nil || retained.Operation.State != "retained_unknown" || retained.Operation.PlanSHA256 != record.Operation.PlanSHA256 || len(retained.Operation.Deleted) != len(record.Operation.Deleted) {
		t.Fatal("review fabricated successful deletion", retained, err)
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, live) {
		t.Fatal("cold review changed live log")
	}
	if err := moduleWrite(verified, map[string]any{"id": id, "cut": cut, "passed": true, "boot_before": proof.Boot, "boot_after": strings.TrimSpace(string(boot)), "actual_SIGKILL_checked_by_coordinator": true, "current_log_untouched": true, "current_inode_preserved": true, "unknown_plan_not_retried": true, "retained": retained, "metadata_fixture_only": true, "source_candidate_only": true, "signed_release_acceptance": false}); err != nil {
		t.Fatal(err)
	}
}
