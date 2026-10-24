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
)

// Opt-in read-only filter agreement after actual external SSH autobans.
// The fixed upstream dump is projected offline; no stream/backend is run.
// This is not a normal signed install or core authorization receipt.
func TestOwnedIntrusionFilterAgreementNative(t *testing.T) {
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
	allowed := map[string]bool{"/usr/sbin/sshd -T": true, "/usr/bin/ss -H -ltnp": true, "/usr/sbin/nft -j list table inet f2b-table": true, "/usr/sbin/nft -j list tables": true}
	events := []string{}
	run := func(ctx context.Context, program string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded managed inspection")
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"show", "fail2ban.service", "--property=MainPID,ActiveState"}) {
			return "MainPID=" + pid + "\nActiveState=active\n", nil
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"is-active", "fail2ban"}) {
			return "active\n", nil
		}
		dump := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionConfigurationDumpScript})
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		if !batch && !dump && !allowed[program+" "+strings.Join(args, " ")] {
			t.Fatal("nonfixed read or mutation attempted", program)
		}
		if dump {
			events = append(events, "dump")
		}
		if batch {
			events = append(events, "batch")
		}
		if program == "/usr/sbin/nft" {
			events = append(events, "kernel")
		}
		return RunCommand(ctx, program, args...)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: security, Run: run})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	runtime, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || !intrusionFilterMetadataValid(runtime.FilterMetadata) || len(runtime.Bans) != 2 || !slices.Equal(runtime.SSHPorts, []int{2882}) {
		t.Fatal("actual runtime filter metadata missing", err)
	}
	runtimeMS := time.Since(before).Milliseconds()

	// Read the same kernel field independently in this owned PID/proc mount.
	// A deliberately stale lifetime must reject the fixed typed setter before
	// its first getter or setter. This is NOT a real PID-reuse simulation.
	processCtx, processCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer processCancel()
	observedStart, startErr := RunCommand(processCtx, "/usr/bin/python3", "-I", "-B", "-c", intrusionProcessIdentityScript+"\nimport sys\nprint(process_start_ticks(int(sys.argv[1])))\n", pid)
	if startErr != nil || observedStart != runtime.ProcessStart+"\n" || !intrusionProcessTicksValid(runtime.ProcessStart) {
		t.Fatal("actual kernel process lifetime missing", startErr)
	}
	wrongStart := "1"
	if runtime.ProcessStart == wrongStart {
		wrongStart = "2"
	}
	limit := runtime.Settings["max_retry"]
	target := limit + 1
	if limit == 20 {
		target = limit - 1
	}
	wrongArgs, argsErr := intrusionScalarMutationArgs(pid, wrongStart, runtime.Policy.Action, intrusionScalarChange{Key: "maxretry", From: strconv.Itoa(limit), To: strconv.Itoa(target)})
	if argsErr != nil {
		t.Fatal(argsErr)
	}
	refusal, rejected := RunCommand(processCtx, "/usr/bin/python3", wrongArgs...)
	if rejected == nil || strings.TrimSpace(refusal) != "{\"format\":0}" {
		t.Fatal("foreign kernel lifetime reached a qualified setter", rejected)
	}

	before = time.Now()
	dump, err := s.readIntrusionEffectiveConfiguration(ctx, runtime, runtime.Settings)
	if err != nil || len(dump.Identity) != 64 {
		t.Fatal("actual disk and live filter metadata do not agree", err)
	}
	dumpMS := time.Since(before).Milliseconds()
	if runtimeMS >= 8000 || dumpMS >= 8000 || !slices.Equal(events, []string{"batch", "kernel", "batch", "kernel", "dump"}) {
		t.Fatal("bounded actual observations changed", events, runtimeMS, dumpMS)
	}
	// The comparison is in the production decoder; do not silently accept a
	// well-formed foreign digest or omit the live reading on a caller's behalf.
	changed := runtime
	changed.FilterMetadata.SHA256 = strings.Repeat("b", 64)
	var actual intrusionEffectiveDump
	if err := json.Unmarshal([]byte(mustMarshalIntrusionFilterDumpForOwnedTest(t, dump, runtime.FilterMetadata)), &actual); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intrusionEffectiveConfigurationDecode(raw, changed, changed.Settings); err == nil {
		t.Fatal("mismatching live filter digest accepted")
	}
	after, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range files {
		if !hardeningBackupSame(files[i], after[i]) {
			t.Fatal("inspection changed owned file", i)
		}
	}
	afterTree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(tree, afterTree) {
		t.Fatal("inspection changed source tree", err)
	}
	for _, name := range []string{intrusionPendingName, intrusionMutationLockName, intrusionJournalDirectory} {
		if _, err := os.Lstat(filepath.Join(security, name)); !os.IsNotExist(err) {
			t.Fatal("readonly route created authority or journal", name, err)
		}
	}
	proof := map[string]any{"ok": true, "actual_filter_getters_and_offline_projection_agree": true, "kernel_process_start_ticks_independently_verified": true, "foreign_start_fixed_actuator_refused": true, "real_PID_reuse_NOT_simulated": true, "readable_metadata_only_not_hidden_matcher_attestation": true, "actual_filter_version": runtime.FilterMetadata.Version, "runtime_ms": runtimeMS, "dump_ms": dumpMS, "unchanged_production_probe_budget_seconds": 8, "real_observations": events, "actual_bans": len(runtime.Bans), "actual_SSH_ports": runtime.SSHPorts, "owned_files_tree_authority_and_runtime_unchanged": true, "declared_isolated_unit_pid_adapter": true, "signed_store_or_core_authorization_acceptance": false}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_FILTER_AGREEMENT:" + base64.StdEncoding.EncodeToString(encoded))
}

func mustMarshalIntrusionFilterDumpForOwnedTest(t *testing.T, dump intrusionEffectiveConfiguration, metadata intrusionFilterMetadata) string {
	t.Helper()
	raw, err := json.Marshal(intrusionEffectiveDump{Format: 1, Commands: dump.Commands, FilterMetadata: &metadata})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
