//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// This opt-in exists only in a private test executable. All external commands
// are positively whitelisted reads; it cannot install/configure/reload/ban,
// create a security lock or authorize any production operation.
func TestOwnedIntrusionInstalledReadOnlyNative(t *testing.T) {
	if os.Getenv("PANEL_INSTALLED_INTRUSION_OBSERVATION") != "24bhld" {
		t.Skip("explicit installed read-only QA observation required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual QA service principal required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13" {
		t.Fatal("not either declared owned QA VM", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != os.Getenv("PANEL_INSTALLED_INTRUSION_BOOT") {
		t.Fatal("original boot changed", err)
	}
	allowed := map[string]bool{
		"/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState": true,
		"/usr/sbin/sshd -T":                              true,
		"/usr/bin/ss -H -ltnp":                           true,
		"/usr/bin/systemctl is-active fail2ban":          true,
		"/usr/bin/fail2ban-client status sshd":           true,
		"/usr/bin/fail2ban-client get sshd actions":      true,
		"/usr/bin/fail2ban-client get sshd banip":        true,
		"/usr/bin/fail2ban-client get sshd maxretry":     true,
		"/usr/bin/fail2ban-client get sshd findtime":     true,
		"/usr/bin/fail2ban-client get sshd bantime":      true,
		"/usr/bin/fail2ban-client get sshd journalmatch": true,
		"/usr/sbin/nft -j list table inet f2b-table":     true,
		"/usr/sbin/nft -j list tables":                   true,
	}
	for _, action := range []string{"nftables", "nftables-multiport"} {
		for _, property := range []string{"name", "port", "protocol", "chain", "table", "table_family", "addr_set", "addr_set?family=inet6", "actionstart"} {
			allowed["/usr/bin/fail2ban-client get sshd action "+action+" "+property] = true
		}
	}
	calls := 0
	read := func(ctx context.Context, program string, args ...string) (string, error) {
		batch := program == "/usr/bin/python3" && len(args) == 5 && args[0] == "-I" && args[1] == "-B" && args[2] == "-c" && args[3] == intrusionReadOnlyBatchScript
		if batch {
			_, err := intrusionFail2banProcess("MainPID=" + args[4] + "\nActiveState=active\n")
			batch = err == nil
		}
		dump := program == "/usr/bin/python3" && len(args) == 4 && args[0] == "-I" && args[1] == "-B" && args[2] == "-c" && args[3] == intrusionConfigurationDumpScript
		if !allowed[program+" "+strings.Join(args, " ")] && !batch && !dump {
			t.Fatalf("non-whitelisted operation forbidden: %s %v", program, args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("read lacks bounded overall deadline")
		}
		calls++
		return RunCommand(ctx, program, args...)
	}
	s := &Service{Config: Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps", Run: read}}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	journal, err := read(ctx, "/usr/bin/fail2ban-client", "get", "sshd", "journalmatch")
	if err != nil || (journal != "Current match filter:\n_SYSTEMD_UNIT=sshd.service + _COMM=sshd\n" && journal != "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd\n") {
		t.Fatal("actual installed journald backend not verified", err)
	}
	out, err := s.inspectIntrusion(ctx)
	if err != nil || !out.Installed || (out.Version != "1.0" && out.Version != "1.0.0") || !out.ServiceActive || !out.ConfigMatches || !out.SSHPortsMatch || !slices.Equal(out.SSHEffectivePorts, []int{22}) || !out.ActiveBansKnown || out.ActiveBans != 0 || len(out.Actions) != 1 || !out.Actions[0].ScopeVerified || out.KernelScopeVerified == out.KernelScopeDeferred || out.Healthy != out.KernelScopeVerified {
		t.Fatal("current installed read-only state unqualified", out, err)
	}
	if out.KernelScopeDeferred && len(out.Warnings) != 1 {
		t.Fatal("deferred state hides another warning", out)
	}
	if calls < 7 || calls > 14 {
		t.Fatal("unexpected fixed read surface", calls)
	}
	runtime, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || !slices.Equal(runtime.SSHPorts, out.SSHEffectivePorts) || len(runtime.Bans) != 0 || runtime.Policy.Name != "sshd" || runtime.Policy.Table != "f2b-table" || runtime.Policy.Chain != "f2b-chain" || runtime.KernelState != "rules_observed" && runtime.KernelState != "table_absent" && runtime.KernelState != "scope_absent" || calls < 14 || calls > 35 {
		t.Fatal("full stable runtime snapshot unqualified", err, calls)
	}
	t.Log("INSTALLED_INTRUSION_RUNTIME_STATE:" + runtime.KernelState)
	configuration, err := s.readIntrusionEffectiveConfiguration(ctx, runtime, runtime.Settings)
	if err != nil || len(configuration.Identity) != 64 {
		t.Fatal("actual strict disk configuration unqualified", err)
	}
	again, err := s.readIntrusionEffectiveConfiguration(ctx, runtime, runtime.Settings)
	if err != nil || again.Identity != configuration.Identity {
		t.Fatal("actual disk configuration changed during read", err)
	}
	t.Log("INSTALLED_INTRUSION_EFFECTIVE_CONFIG:" + configuration.Identity)
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || len(tree.Entries) < 100 || tree.Bytes < 100000 {
		t.Fatal("actual complete disk inventory unqualified", err)
	}
	treeAgain, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(tree, treeAgain) {
		t.Fatal("actual complete disk inventory changed", err)
	}
	t.Logf("INSTALLED_INTRUSION_CONFIG_TREE:%d:%d", len(tree.Entries), tree.Bytes)
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > 8192 {
		t.Fatal("inspection result invalid or oversized", err)
	}
	t.Log("INSTALLED_INTRUSION_READONLY:" + base64.StdEncoding.EncodeToString(raw))
	t.Log("PASS actual installed read-only observation; NOT an application update, ban, SSH authentication journey or all-50 acceptance")
}
