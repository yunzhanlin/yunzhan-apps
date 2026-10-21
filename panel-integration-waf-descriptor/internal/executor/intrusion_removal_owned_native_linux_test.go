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

// Real upstream configuration parsing in NEW owned namespaces only. This
// reads the actual daemon, clones its verified config and tests -c privately;
// it does NOT delete an installed Jail, uninstall any app or claim API/store
// or SSH-authentication/journal journey acceptance.
func TestOwnedIntrusionRemovalCandidateNative(t *testing.T) {
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
			t.Fatal("unbounded owned candidate observation")
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"show", "fail2ban.service", "--property=MainPID,ActiveState"}) {
			return "MainPID=" + pid + "\nActiveState=active\n", nil // Declared test-only unit adapter.
		}
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		dump := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionConfigurationDumpScript})
		candidate := program == "/usr/bin/python3" && len(args) == 6 && slices.Equal(args[:5], []string{"-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate"}) && filepath.Dir(args[5]) == filepath.Join(security, intrusionRemovalCacheName) && intrusionRemovalCopyName.MatchString(filepath.Base(args[5]))
		if candidate {
			candidateTests++
		}
		if !allowed[program+" "+strings.Join(args, " ")] && !batch && !dump && !candidate {
			t.Fatal("nonfixed candidate operation or actuator forbidden", program)
		}
		return RunCommand(ctx, program, args...)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: security, Run: run})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	beforeFiles, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	beforeTree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || before.Process != pid || before.Settings["max_retry"] != 5 || before.Settings["find_time_minutes"] != 10 || before.Settings["ban_time_minutes"] != 60 {
		t.Fatal("actual managed original limits not proven", err)
	}
	full, err := s.readIntrusionEffectiveConfiguration(ctx, before, before.Settings)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := s.readIntrusionRemovalCandidate(ctx, lock, beforeTree, hardeningJournalFromBackup(beforeFiles[0]), before, full.Identity)
	if err != nil || candidateTests != 1 || candidate.Settings["max_retry"] != 7 || candidate.Settings["find_time_minutes"] != 12 || candidate.Settings["ban_time_minutes"] != 120 || !slices.Equal(candidate.Ports, []int{22}) || candidate.EffectiveIdentity != full.Identity {
		t.Fatal("actual upstream underlying limits were not independently derived", candidate, candidateTests, err)
	}
	afterTree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(beforeTree, afterTree) {
		t.Fatal("real candidate test altered installed source", err)
	}
	afterFiles, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range beforeFiles {
		if !hardeningBackupSame(beforeFiles[i], afterFiles[i]) {
			t.Fatal("candidate test altered installed record or owned Jail", i)
		}
	}
	after, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only candidate changed actual daemon, SSH or kernel scope", err)
	}
	cache, err := os.OpenRoot(filepath.Join(security, intrusionRemovalCacheName))
	if err != nil {
		t.Fatal(err)
	}
	names, err := intrusionConfigurationDirectoryNames(cache)
	cache.Close()
	if err != nil || len(names) != 0 {
		t.Fatal("new verified candidate was not cleaned safely", names, err)
	}
	proof := map[string]any{"ok": true, "actual_upstream_candidate_tests": candidateTests, "actual_before_settings": before.Settings, "actual_underlying_settings": candidate.Settings, "actual_underlying_ports": candidate.Ports, "effective_identity": candidate.EffectiveIdentity, "source_files_records_daemon_SSH_kernel_preserved": true, "only_new_verified_copy_removed": true, "declared_isolated_unit_pid_adapter": true, "normal_API_store_or_uninstall_acceptance": false, "SSH_authentication_journald_journey": false}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_CANDIDATE:" + base64.StdEncoding.EncodeToString(encoded))
}
