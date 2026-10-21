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

// Opt-in actual executor API journey. The parent creates real failed SSH
// authentications in a separate, connected client network namespace. This is
// not a signed install, core authorization or an application-store receipt.
func TestOwnedIntrusionSSHUnbanNative(t *testing.T) {
	if os.Getenv("PANEL_OWNED_INTRUSION_CANDIDATE") != "24bhtm" {
		t.Skip("explicit owned namespaces required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned root namespace required")
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
		t.Fatal("not declared QA VM")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != os.Getenv("PANEL_OWNED_INTRUSION_BOOT") {
		t.Fatal("original boot changed")
	}
	base := os.Getenv("PANEL_OWNED_INTRUSION_BASE")
	if !regexp.MustCompile(`^/var/lib/panel-executor/intrusion-netns24bhom-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(base) {
		t.Fatal("fixed owned fixture root required")
	}
	for _, item := range []struct{ live, owned string }{{"/etc/fail2ban", "private-fail2ban"}, {"/etc/ssh", "private-ssh"}, {"/run/fail2ban", "private-run"}, {"/run", "private-run-root"}} {
		a, aErr := os.Stat(item.live)
		z, zErr := os.Stat(filepath.Join(base, item.owned))
		if aErr != nil || zErr != nil || !os.SameFile(a, z) {
			t.Fatal("private mount not proven", item.live)
		}
	}
	client, err := os.Stat("/run/netns/yunzhan-owned-client")
	server, serverErr := os.Stat("/proc/self/ns/net")
	if err != nil || serverErr != nil || client.Sys().(*syscall.Stat_t).Ino == server.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("distinct owned SSH client network required")
	}
	pid := os.Getenv("PANEL_OWNED_INTRUSION_PID")
	if _, err := intrusionFail2banProcess("MainPID=" + pid + "\nActiveState=active\n"); err != nil {
		t.Fatal(err)
	}
	security := filepath.Join(base, "security")
	allowed := map[string]bool{
		"/usr/sbin/sshd -T": true, "/usr/bin/ss -H -ltnp": true,
		"/usr/sbin/nft -j list table inet f2b-table": true, "/usr/sbin/nft -j list tables": true,
		"/usr/bin/fail2ban-client status": true, "/usr/bin/fail2ban-client status sshd": true,
		"/usr/bin/fail2ban-client status other": true,
	}
	setters := 0
	events := []string{}
	run := func(ctx context.Context, program string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded API operation")
		}
		if (program == "/usr/bin/systemctl" || program == "systemctl") && slices.Equal(args, []string{"is-active", "fail2ban"}) {
			return "active\n", nil
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"show", "fail2ban.service", "--property=MainPID,ActiveState"}) {
			return "MainPID=" + pid + "\nActiveState=active\n", nil
		}
		if program == "fail2ban-client" {
			program = "/usr/bin/fail2ban-client"
		}
		setter := program == "/usr/bin/fail2ban-client" && slices.Equal(args, []string{"set", "sshd", "unbanip", "192.0.2.2"})
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		if !setter && !batch && !allowed[program+" "+strings.Join(args, " ")] {
			t.Fatal("nonfixed command attempted", program, args)
		}
		if setter {
			setters++
			if setters != 1 {
				t.Fatal("unban setter repeated")
			}
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := []int64{}
	inspect := func(bans int) {
		t.Helper()
		events = nil
		start := time.Now()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/intrusion-prevention/inspection", nil).WithContext(ctx))
		elapsed = append(elapsed, time.Since(start).Milliseconds())
		var out intrusionInspection
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Installed || out.Version != "1.1.0" || !out.Healthy || !out.ConfigMatches || !out.ServiceActive || !out.SSHPortsMatch || !out.KernelScopeVerified || out.KernelScopeDeferred || !out.ActiveBansKnown || out.ActiveBans != bans || !slices.Equal(out.SSHListeningPorts, []int{2882}) || !slices.Equal(out.SSHEffectivePorts, []int{2882}) || len(out.Actions) != 1 || !out.Actions[0].KernelIPv4 || !out.Actions[0].KernelIPv6 || len(out.Warnings) != 0 {
			t.Fatal("actual managed inspection failed", w.Code, w.Body.String())
		}
		if !slices.Equal(events, []string{"batch", "kernel", "batch"}) || elapsed[len(elapsed)-1] >= 8000 {
			t.Fatal("real bounded batches not bracketing kernel", events, elapsed)
		}
		for _, private := range []string{"actionstart", "actionban", "kernel_before", "bans_before", "192.0.2.2", "2001:db8:1::2"} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("private metadata leaked", private)
			}
		}
	}
	inspect(2)
	post := func(body string, status int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/security/fail2ban/unban", strings.NewReader(body)).WithContext(ctx))
		if w.Code != status {
			t.Fatal("unban API status", status, w.Code, w.Body.String())
		}
		if status == 200 && !strings.Contains(w.Body.String(), `"unbanned":true`) {
			t.Fatal("unban confirmation missing", w.Body.String())
		}
	}
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	post(`{"jail":"sshd","ip":"2001:db8:1::2"}`, 409)
	if setters != 0 {
		t.Fatal("held transaction permitted setter")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	post(`{"jail":"sshd","ip":"192.0.2.2"}`, 200)
	post(`{"jail":"sshd","ip":"192.0.2.2"}`, 404)
	post(`{"jail":"sshd;exit","ip":"2001:db8:1::2"}`, 400)
	post(`{"jail":"sshd","ip":"invalid"}`, 400)
	if setters != 1 {
		t.Fatal("expected exactly one real setter", setters)
	}
	inspect(1)
	after, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range files {
		if !hardeningBackupSame(files[i], after[i]) {
			t.Fatal("unban changed configuration", i)
		}
	}
	afterTree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(tree, afterTree) {
		t.Fatal("configuration tree changed", err)
	}
	for _, name := range []string{intrusionPendingName, intrusionJournalDirectory} {
		if _, err := os.Lstat(filepath.Join(security, name)); !os.IsNotExist(err) {
			t.Fatal("unban invented transaction", name, err)
		}
	}
	info, err := os.Lstat(filepath.Join(security, intrusionMutationLockName))
	if err != nil || !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 {
		t.Fatal("unban lock identity invalid", err)
	}
	proof := map[string]any{"ok": true, "actual_normal_unban_route": true, "actual_normal_inspection_route": true, "real_read_batches_per_inspection": []string{"batch", "kernel", "batch"}, "inspection_elapsed_ms": elapsed, "unchanged_production_probe_budget_seconds": 8, "actual_bans_before": 2, "actual_bans_after": 1, "exact_actual_setters": setters, "exclusive_lock_blocks_other_family": true, "duplicate_unban_not_retried": true, "configuration_and_tree_preserved": true, "private_metadata_not_exposed": true, "declared_isolated_unit_pid_adapter": true, "signed_store_or_core_authorization_acceptance": false}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_SSH_UNBAN:" + base64.StdEncoding.EncodeToString(encoded))
}
