//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var wafLogColdCuts = []string{"intent-durable", "snapshot-created", "snapshot-durable", "prepared-durable", "truncate-durable", "completed-durable", "remove-intent-durable", "snapshot-unlink-durable", "intent-index-stage-created", "intent-index-stage-written", "intent-index-stage-durable", "prepared-index-stage-created", "prepared-index-stage-written", "prepared-index-stage-durable", "completed-index-stage-created", "completed-index-stage-written", "completed-index-stage-durable"}

// Only the explicit private coordinator on the two disposable VMs may invoke
// this. Every file is in a new private QA filesystem root, never the active
// Nginx log. It proves real SIGKILL/cold filesystem recovery, not an error-return
// simulation, and does not claim native request protection from this fixture.
func TestWAFBodyLogColdQA(t *testing.T) {
	id, cut, phase := os.Getenv("PANEL_WAF_LOG_COLD_QA_ID"), os.Getenv("PANEL_WAF_LOG_COLD_QA_CUT"), os.Getenv("PANEL_WAF_LOG_COLD_QA_PHASE")
	if id == "" && cut == "" && phase == "" {
		t.Skip("explicit disposable metadata cold coordinator required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse unknown/main/non-root metadata cold test")
	}
	valid := false
	for _, c := range wafLogColdCuts {
		if c == cut {
			valid = true
		}
	}
	if !valid || (phase != "prepare" && phase != "verify") {
		t.Fatal("unknown cold case")
	}
	base := filepath.Join("/var/lib/panel-executor/waf-log-cold-qa", id)
	if err := ownedRuntimePath(base, true); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(base, cut)
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
		t.Fatal("metadata fixture must not run native commands")
		return "", nil
	}})
	ctx := context.Background()
	path := s.systemPath(wafBodyLogPath)
	data := []byte("2026/10/08 01:00:00 [warn] 321#321: yunzhan_waf_body rule=941100 phase=2 severity=2 disruptive=1 site=" + strings.Repeat("b", 32) + "\n")
	proofPath := filepath.Join(caseDir, "prepared.json")
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	if phase == "prepare" {
		if _, err := os.Lstat(proofPath); !os.IsNotExist(err) {
			t.Fatal("prior cold evidence exists")
		}
		if err := s.prepareWAFBodyLog(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0640); err != nil {
			t.Fatal(err)
		}
		checkpoint := func(stage string) error {
			if stage != cut {
				return nil
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			proof := map[string]any{"id": id, "cut": cut, "pid": os.Getpid(), "boot_before": strings.TrimSpace(string(boot)), "current_sha256": core.Hash(string(current)), "current_bytes": len(current), "current_inode": st.Sys().(*syscall.Stat_t).Ino, "state": "waiting_for_SIGKILL", "metadata_fixture_only": true, "source_candidate_only": true, "signed_release_acceptance": false}
			if err := moduleWrite(proofPath, proof); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Second)
			}
		}
		if strings.HasPrefix(cut, "remove-") || cut == "snapshot-unlink-durable" {
			entry, err := s.snapshotAndTruncateWAFBodyLog(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0640); err != nil {
				t.Fatal(err)
			}
			if err := s.removeWAFBodyLogArchiveAt(ctx, entry.ID, entry.SHA256, checkpoint); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := s.snapshotAndTruncateWAFBodyLogAt(ctx, checkpoint); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("cold checkpoint not reached")
	}
	proofData, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		ID    string `json:"id"`
		Cut   string `json:"cut"`
		PID   int    `json:"pid"`
		Boot  string `json:"boot_before"`
		SHA   string `json:"current_sha256"`
		Bytes int    `json:"current_bytes"`
		Inode uint64 `json:"current_inode"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(proofData, &proof); err != nil {
		t.Fatal(err)
	}
	if proof.ID != id || proof.Cut != cut || proof.State != "waiting_for_SIGKILL" || proof.Boot == strings.TrimSpace(string(boot)) {
		t.Fatal("missing distinct real cold boot", proof)
	}
	verified := filepath.Join(caseDir, "verified.json")
	if _, err := os.Lstat(verified); !os.IsNotExist(err) {
		t.Fatal("never overwrite completed cold evidence")
	}
	before, err := os.ReadFile(path)
	if err != nil || len(before) != proof.Bytes || core.Hash(string(before)) != proof.SHA {
		t.Fatal("cold boot changed owned current log", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Sys().(*syscall.Stat_t).Ino != proof.Inode {
		t.Fatal("current log inode changed")
	}
	stages, err := s.wafBodyLogIndexStages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range stages {
		if _, err := s.retainWAFBodyLogIndexStage(ctx, stage.ID, strings.Repeat("0", 64)); err == nil {
			t.Fatal("stale staged index digest accepted")
		}
		retained, err := s.retainWAFBodyLogIndexStage(ctx, stage.ID, stage.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if !core.ValidID(retained) {
			t.Fatal("missing preserved pending inode")
		}
	}
	pending, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range pending {
		if entry.Archive.State == "removing" {
			if err := s.removeWAFBodyLogArchive(ctx, entry.Archive.ID, strings.Repeat("0", 64)); err == nil {
				t.Fatal("wrong digest deletion resumed")
			}
			if err := s.removeWAFBodyLogArchive(ctx, entry.Archive.ID, entry.Archive.SHA256); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := s.retainWAFBodyLogSnapshot(ctx, entry); err != nil {
				t.Fatal(err)
			}
			if err := s.retainWAFBodyLogSnapshot(ctx, entry); err == nil {
				t.Fatal("stale uncertain recovery accepted")
			}
		}
	}
	archives, err := s.wafBodyLogArchives()
	if err != nil {
		t.Fatal(err)
	}
	for _, archive := range archives {
		if cut != "completed-durable" && archive.State == "completed" {
			t.Fatal("unknown interrupted rotation fabricated as success", archive)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives/"+archive.ID, nil))
		if w.Code != 200 {
			t.Fatal("retained snapshot cannot be explicitly exported", w.Code, w.Body.String())
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || core.Hash(string(after)) != proof.SHA {
		t.Fatal("cold recovery double truncated or altered current log", err)
	}
	if err := moduleWrite(verified, map[string]any{"id": id, "cut": cut, "passed": true, "boot_before": proof.Boot, "boot_after": strings.TrimSpace(string(boot)), "actual_SIGKILL_checked_by_coordinator": true, "current_log_untouched": true, "current_inode_preserved": true, "index_stages_preserved": stages, "pending_before": pending, "archives_after": archives, "metadata_fixture_only": true, "source_candidate_only": true, "signed_release_acceptance": false}); err != nil {
		t.Fatal(err)
	}
}
