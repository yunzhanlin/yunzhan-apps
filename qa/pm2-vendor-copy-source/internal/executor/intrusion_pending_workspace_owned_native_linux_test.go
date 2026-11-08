//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Opt-in NEW owned pending-workspace observation. Preparing a private
// original is not an install/uninstall or a real queue/API/store receipt.
// No scalar, port-template, kernel, ban or service mutation is permitted.
func TestOwnedIntrusionPendingWorkspaceNative(t *testing.T) {
	if os.Getenv("PANEL_OWNED_INTRUSION_CANDIDATE") != "24bhtm" {
		t.Skip("explicit owned triple-namespace candidate fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual owned root namespace required")
	}
	for _, kind := range []string{"net", "pid", "mnt"} {
		host, err := strconv.ParseUint(os.Getenv("PANEL_OWNED_HOST_"+strings.ToUpper(kind)+"_INODE"), 10, 64)
		info, statErr := os.Stat("/proc/self/ns/" + kind)
		if err != nil || host == 0 || statErr != nil || info.Sys().(*syscall.Stat_t).Ino == host {
			t.Fatal("original host namespace forbidden", kind)
		}
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13" {
		t.Fatal("not declared owned QA VM")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != os.Getenv("PANEL_OWNED_INTRUSION_BOOT") {
		t.Fatal("original boot changed")
	}
	base := os.Getenv("PANEL_OWNED_INTRUSION_BASE")
	if !regexp.MustCompile(`^/var/lib/panel-executor/intrusion-netns24bhom-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(base) {
		t.Fatal("fixed owned fixture root required")
	}
	for _, item := range []struct{ live, owned string }{{"/etc/fail2ban", "private-fail2ban"}, {"/etc/ssh", "private-ssh"}, {"/run/fail2ban", "private-run"}} {
		a, aErr := os.Stat(item.live)
		z, zErr := os.Stat(filepath.Join(base, item.owned))
		if aErr != nil || zErr != nil || !os.SameFile(a, z) {
			t.Fatal("private bound directory not proven", item.live)
		}
	}
	pid := os.Getenv("PANEL_OWNED_INTRUSION_PID")
	if _, err := intrusionFail2banProcess("MainPID=" + pid + "\nActiveState=active\n"); err != nil {
		t.Fatal(err)
	}

	security := filepath.Join(base, "security")
	candidateTests := 0
	allowed := map[string]bool{"/usr/sbin/sshd -T": true, "/usr/bin/ss -H -ltnp": true, "/usr/sbin/nft -j list table inet f2b-table": true, "/usr/sbin/nft -j list tables": true}
	run := func(ctx context.Context, program string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded native pending observation")
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"show", "fail2ban.service", "--property=MainPID,ActiveState"}) {
			return "MainPID=" + pid + "\nActiveState=active\n", nil
		}
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		dump := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionConfigurationDumpScript})
		candidate := program == "/usr/bin/python3" && len(args) == 6 && slices.Equal(args[:5], []string{"-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate"}) && filepath.Dir(args[5]) == filepath.Join(security, intrusionRemovalCacheName) && intrusionRemovalCopyName.MatchString(filepath.Base(args[5]))
		if candidate {
			candidateTests++
		}
		if !allowed[program+" "+strings.Join(args, " ")] && !batch && !dump && !candidate {
			t.Fatal("workspace/preflight attempted a nonfixed read or mutation", program)
		}
		return RunCommand(ctx, program, args...)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: security, Run: run})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := core.ID()
	ctx = context.WithValue(ctx, intrusionJobContextKey{}, id)
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	p, raw, err := s.intrusionPrepareOperation(ctx, lock, "uninstall", nil)
	if err != nil {
		lock.Close()
		t.Fatal("owned original prepare failed", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.inspectIntrusionWorkspace(ctx)
	if err != nil || view.StateKnown || view.Current != nil || view.Pending == nil || !view.Pending.RecoveryPermitted || view.Pending.ID != id || view.Pending.SHA256 != hardeningJournalDigest(raw) || view.Pending.State != "pending" || !view.Pending.DurationChangesExistingBans || len(view.History) != 0 || candidateTests != 1 {
		t.Fatal("actual pending workspace misclassified original or required mutation", err)
	}
	metadata, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"installed\"", "\"healthy\"", "\"dump\"", "\"kernel_before\"", "\"bans_before\"", "\"configuration_before\"", "127.0.0.2", "2001:db8::2"} {
		if strings.Contains(string(metadata), forbidden) {
			t.Fatal("pending workspace leaked private authority or false current health")
		}
	}
	afterFiles, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range files {
		if !hardeningBackupSame(files[i], afterFiles[i]) {
			t.Fatal("read-only workspace changed owned file", i)
		}
	}
	afterTree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(tree, afterTree) {
		t.Fatal("read-only workspace changed source tree", err)
	}
	after, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only workspace changed daemon, SSH, bans, limits or kernel", err)
	}
	_, again, err := s.intrusionJournalPending()
	if err != nil || string(raw) != string(again) {
		t.Fatal("workspace changed or closed original", err)
	}
	reader, err := s.intrusionObservationLock()
	if err != nil || reader == nil {
		t.Fatal("real read-only descriptor unavailable", err)
	}
	if err := s.intrusionJournalRequireLock(reader); err == nil {
		reader.Close()
		t.Fatal("real read-only descriptor became write authority")
	}
	reader.Close()
	writer, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal("workspace retained an SH lock after return", err)
	}
	err = s.intrusionJournalRequireOriginal(writer, p, raw)
	writer.Close()
	if err != nil {
		t.Fatal("workspace changed original mutation authority", err)
	}
	proof := map[string]any{"ok": true, "original_id": id, "plan_sha256": hardeningJournalDigest(raw), "pending_still_exact_and_unclosed": true, "state_known": view.StateKnown, "current_health_or_installed_object": view.Current != nil, "actual_readonly_recovery_preflight": view.Pending.RecoveryPermitted, "source_files_daemon_bans_limits_SSH_kernel_preserved": true, "no_scalar_port_template_nft_commands": true, "private_metadata_not_exposed": true, "shared_lock_released_and_original_still_valid": true, "actual_upstream_candidate_tests": candidateTests, "declared_isolated_unit_pid_adapter": true, "normal_API_store_or_SSH_authentication_journey": false}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_WORKSPACE:" + base64.StdEncoding.EncodeToString(encoded))
}
