//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
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

// Opt-in declared1.1 fixture: actual normal inspection route, not a package,
// queue/install receipt, SSH authentication journey or all50 acceptance.
// Both real read batches must straddle the actual kernel observation.
func TestOwnedIntrusionManagedInspectionNative(t *testing.T) {
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
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		if !batch && !allowed[program+" "+strings.Join(args, " ")] {
			t.Fatal("nonfixed read or mutation attempted", program)
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
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/intrusion-prevention/inspection", nil).WithContext(ctx))
	elapsed := time.Since(before)
	var out intrusionInspection
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Installed || out.Version != "1.1.0" || !out.Healthy || !out.ConfigMatches || !out.ServiceActive || !out.SSHPortsMatch || !out.KernelScopeVerified || out.KernelScopeDeferred || !out.ActiveBansKnown || out.ActiveBans != 2 || !slices.Equal(out.SSHListeningPorts, []int{2882}) || !slices.Equal(out.SSHEffectivePorts, []int{2882}) || len(out.Actions) != 1 || !out.Actions[0].KernelIPv4 || !out.Actions[0].KernelIPv6 || len(out.Warnings) != 0 {
		t.Fatal("normal managed1.1 route not qualified", w.Code, w.Body.String())
	}
	if !slices.Equal(events, []string{"batch", "kernel", "batch"}) {
		t.Fatal("actual batches were prefetched, repeated or did not bracket kernel", events)
	}
	for _, private := range []string{"actionstart", "actionban", "kernel_before", "bans_before", "127.0.0.2", "2001:db8::2"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("private authority escaped normal inspection", private)
		}
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
	proof := map[string]any{"ok": true, "actual_normal_inspection_route": true, "declared_managed1_1_fixture_not_install_receipt": true, "real_read_batches": events, "normal_inspection_elapsed_ms": elapsed.Milliseconds(), "unchanged_production_probe_budget_seconds": 8, "actual_both_kernel_families": true, "actual_SSH_ports": out.SSHListeningPorts, "actual_active_bans": out.ActiveBans, "owned_files_tree_and_authority_unchanged": true, "private_metadata_not_exposed": true, "declared_isolated_unit_pid_adapter": true, "normal_store_or_SSH_authentication_journey": false}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_MANAGED_INSPECTION:" + base64.StdEncoding.EncodeToString(encoded))
}
