//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
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

// Opt-in NEW private triple-namespace removal transaction. Only this fresh
// fixture owns the three disposable panel files. Existing host/reference apps
// are never uninstalled. This is NOT normal API/store or SSH-auth acceptance.
func TestOwnedIntrusionRemovalTransactionNative(t *testing.T) {
	intrusionOwnedRemovalNative(t, false)
}

func TestOwnedIntrusionRemovalLifecycleNative(t *testing.T) {
	intrusionOwnedRemovalNative(t, true)
}

func intrusionOwnedRemovalNative(t *testing.T, throughController bool) {
	if os.Getenv("PANEL_OWNED_INTRUSION_REMOVAL") != "24bhtu" {
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
	candidateTests, scalarSets := 0, 0
	var original *intrusionJournalPlan
	var nativeService *Service
	type measuredCall struct {
		Calls   int     `json:"calls"`
		Seconds float64 `json:"seconds"`
		Errors  int     `json:"errors"`
	}
	measurements := map[string]*measuredCall{}
	profileStarted := time.Now()
	defer func() {
		// Test-only timings, no command arguments, configuration or IP data.
		encoded, err := json.Marshal(map[string]any{"total_seconds": time.Since(profileStarted).Seconds(), "calls": measurements})
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("OWNED_REMOVAL_PROFILE:" + string(encoded))
	}()
	allowed := map[string]bool{"/usr/sbin/sshd -T": true, "/usr/bin/ss -H -ltnp": true, "/usr/sbin/nft -j list table inet f2b-table": true, "/usr/sbin/nft -j list tables": true}
	run := func(ctx context.Context, program string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded native removal operation")
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
		if throughController && original == nil && program == "/usr/bin/python3" && len(args) == 10 && args[3] == intrusionScalarMutationScript {
			// Test-only read of the controller's already durable original.
			// No caller-selected PID, relaxed actuator or second prepare.
			plan, _, err := nativeService.intrusionJournalPending()
			job, jobErr := intrusionOriginalJob(ctx)
			if err != nil || jobErr != nil || plan.ID != job || plan.Action != "uninstall" || plan.ProcessBefore != pid {
				t.Fatal("controller scalar lacks the actual durable original", err)
			}
			original = &plan
		}
		scalar := false
		if program == "/usr/bin/python3" && len(args) == 10 && args[3] == intrusionScalarMutationScript && original != nil {
			change := intrusionScalarChange{Key: args[5], From: args[7], To: args[8]}
			fixed := map[string][2]string{"maxretry": {"5", "7"}, "findtime": {"600", "720"}, "bantime": {"3600", "7200"}}
			pair, ok := fixed[change.Key]
			expected, err := intrusionScalarMutationArgs(pid, original.ProcessStartBefore, "nftables", change)
			scalar = ok && pair == [2]string{change.From, change.To} && err == nil && slices.Equal(args, expected)
			if scalar {
				scalarSets++
			}
		}
		if !allowed[program+" "+strings.Join(args, " ")] && !batch && !dump && !candidate && !scalar {
			t.Fatal("nonfixed native removal operation or port/kernel actuator forbidden", program)
		}
		class := "fixed-read:" + filepath.Base(program)
		switch {
		case batch:
			class = "readonly-batch"
		case dump:
			class = "effective-dump"
		case candidate:
			class = "private-candidate"
		case scalar:
			class = "fixed-scalar"
		}
		started := time.Now()
		out, runErr := RunCommand(ctx, program, args...)
		if measurements[class] == nil {
			measurements[class] = &measuredCall{}
		}
		value := measurements[class]
		value.Calls++
		value.Seconds += time.Since(started).Seconds()
		if runErr != nil {
			value.Errors++
		}
		return out, runErr
	}
	s := New(Config{SystemRoot: "/", SecurityDir: security, Run: run, RunInput: func(context.Context, []byte, string, ...string) (string, error) {
		t.Fatal("unchanged underlying port must not write kernel")
		return "", errors.New("forbidden kernel write")
	}})
	nativeService = s
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := core.ID()
	ctx = context.WithValue(ctx, intrusionJobContextKey{}, id)
	began := time.Now()
	var p intrusionJournalPlan
	var raw []byte
	if throughController {
		var steps []string
		add := func(v string) { steps = append(steps, v) }
		err = s.applyIntrusionOperation(ctx, nil, "uninstall", add)
		if err != nil || len(steps) != 3 || !strings.Contains(steps[0], "到期时间会随新策略改变") {
			t.Fatal("actual original controller or explicit duration semantics failed", err)
		}
		inventory, readErr := s.intrusionJournalInventoryRead()
		if readErr != nil {
			t.Fatal(readErr)
		}
		p = inventory.Records[id].Plan
		raw, err = intrusionJournalEncode(p)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.applyIntrusionOperation(ctx, nil, "uninstall", add); err != nil || len(steps) != 4 || scalarSets != 3 || candidateTests != 1 {
			t.Fatal("controller replayed committed removal", err)
		}
	} else {
		lock, lockErr := s.intrusionMutationLock()
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		defer lock.Close()
		p, raw, err = s.intrusionPrepareOperation(ctx, lock, "uninstall", nil)
		if err != nil {
			t.Fatal(err)
		}
		original = &p
		err = s.intrusionJournalAdvance(ctx, lock, p, raw, "committed", "")
	}
	t.Log("native original controller or direct prepare+advance seconds", time.Since(began).Seconds())
	if err != nil || p.ID != id || p.Action != "uninstall" || p.ProcessBefore != pid || candidateTests != 1 || !slices.Equal(p.BeforePolicy.Ports, []int{22}) || !slices.Equal(p.TargetPorts, []int{22}) || !slices.Equal(intrusionJournalObservedSSHPorts(p), []int{2882}) || !maps.Equal(p.TargetSettings, map[string]int{"max_retry": 7, "find_time_minutes": 12, "ban_time_minutes": 120}) {
		t.Fatal("native removal original not independently derived", err)
	}
	for _, f := range p.Files {
		if f.After.Exists {
			t.Fatal("removal invented installed target")
		}
	}
	t.Log("native removal prepare+advance seconds", time.Since(began).Seconds())
	if err != nil || scalarSets != 3 || candidateTests != 1 {
		t.Fatal("native removal transaction incomplete or repeated operations", err, scalarSets, candidateTests)
	}
	for _, name := range s.intrusionJournalPaths() {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned panel file remains", name, err)
		}
	}
	if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removal original pending not closed", err)
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil || !intrusionTerminalMatches(inventory.Records[id], p, raw, "committed", "") {
		t.Fatal("native removal lacks immutable original terminal", err)
	}
	live, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || live.Process != pid || !maps.Equal(live.Settings, p.TargetSettings) || !slices.Equal(live.Policy.Ports, []int{22}) || !slices.Equal(live.SSHPorts, []int{2882}) || live.Policy.MaxMatches != 5 || len(live.Bans) != 2 || !reflect.DeepEqual(live.Policy, p.BeforePolicy) || !reflect.DeepEqual(live.Recipe, p.ActionBefore) {
		t.Fatal("native removal changed unrelated daemon, capacity or SSH/kernel policy", err)
	}
	cache, err := os.OpenRoot(filepath.Join(security, intrusionRemovalCacheName))
	if err != nil {
		t.Fatal(err)
	}
	names, err := intrusionConfigurationDirectoryNames(cache)
	cache.Close()
	if err != nil || len(names) != 0 {
		t.Fatal("new copy not safely cleaned", err)
	}
	proof := map[string]any{"ok": true, "original_id": id, "plan_sha256": hardeningJournalDigest(raw), "terminal_state": "committed", "lifetime_action": "uninstall", "actual_upstream_candidate_tests": candidateTests, "scalar_sets": scalarSets, "port_template_nft_writes": 0, "actual_underlying_settings": live.Settings, "actual_underlying_ports": live.Policy.Ports, "unchanged_SSH_ports": live.SSHPorts, "server_pid": pid, "original_bans_filters_capacity_and_other_Jail_preserved": true, "only_three_owned_panel_files_removed": true, "declared_isolated_unit_pid_adapter": true, "normal_API_store_acceptance": false, "SSH_authentication_journald_journey": false}
	proof["through_original_controller"] = throughController
	proof["committed_original_replay_performed_no_writes"] = throughController
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_REMOVAL:" + base64.StdEncoding.EncodeToString(encoded))
}
