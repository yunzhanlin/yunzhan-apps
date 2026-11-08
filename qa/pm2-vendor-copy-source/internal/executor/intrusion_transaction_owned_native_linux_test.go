//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Opt-in PRIVATE executable only. The Python fixture independently binds its
// own config directories and socket in fresh net/PID/mount namespaces. The
// single declared unit-PID adapter is test-only: this is genuine Fail2ban,
// systemd-journal backend, SSH listener and nft, NOT a normal service-unit,
// SSH-authentication-log or application-store installation acceptance claim.
func TestOwnedIntrusionTransactionNative(t *testing.T) {
	intrusionOwnedTransactionNative(t, false)
}

func TestOwnedIntrusionRecoveryNative(t *testing.T) {
	intrusionOwnedTransactionNative(t, true)
}

func intrusionOwnedTransactionNative(t *testing.T, recoveryOnly bool) {
	if os.Getenv("PANEL_OWNED_INTRUSION_TRANSACTION") != "24bhom" {
		t.Skip("explicit owned triple-namespace transaction fixture required")
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
	allowed := map[string]bool{"/usr/sbin/sshd -T": true, "/usr/bin/ss -H -ltnp": true, "/usr/sbin/nft -j list table inet f2b-table": true, "/usr/sbin/nft -j list tables": true}
	scalars, templates, checks, applies := 0, 0, 0, 0
	fault := os.Getenv("PANEL_OWNED_INTRUSION_FAULT")
	if fault != "" && (fault != "template-flush-reply" || os.Getenv("PANEL_OWNED_INTRUSION_LIFETIME") != "install") {
		t.Fatal("unknown private fault fixture")
	}
	phase := os.Getenv("PANEL_OWNED_INTRUSION_SPLIT_PHASE")
	if phase != "" && phase != "forward" && phase != "recover" || recoveryOnly && (phase != "recover" || fault == "") || !recoveryOnly && phase == "recover" {
		t.Fatal("unknown or inconsistent owned job phase")
	}
	recovering, lost := recoveryOnly, false
	var nativeOriginal *intrusionJournalPlan
	run := func(ctx context.Context, program string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded native operation")
		}
		if program == "/usr/bin/systemctl" && slices.Equal(args, []string{"show", "fail2ban.service", "--property=MainPID,ActiveState"}) {
			// The isolated daemon is not managed by the host's real unit. Do
			// not call systemctl or expose an arbitrary PID/script adapter.
			return "MainPID=" + pid + "\nActiveState=active\n", nil
		}
		batch := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionReadOnlyBatchScript, pid})
		dump := program == "/usr/bin/python3" && slices.Equal(args, []string{"-I", "-B", "-c", intrusionConfigurationDumpScript})
		scalar := false
		if program == "/usr/bin/python3" && len(args) == 10 && args[3] == intrusionScalarMutationScript {
			change := intrusionScalarChange{Key: args[5], From: args[7], To: args[8]}
			if nativeOriginal == nil {
				t.Fatal("native scalar before durable original process identity")
			}
			expected, e := intrusionScalarMutationArgs(pid, nativeOriginal.ProcessStartBefore, "nftables", change)
			scalar = e == nil && slices.Equal(expected, args) && change.Key == "port" && change.From == "22" && change.To == "2882"
			if scalar {
				scalars++
			}
		}
		template := false
		if program == "/usr/bin/python3" && len(args) == 13 && args[3] == intrusionPortTemplateMutationScript {
			if nativeOriginal == nil {
				t.Fatal("native template step before immutable original prepare")
			}
			after, err := intrusionPortRecipeTarget(*nativeOriginal)
			if err != nil {
				t.Fatal(err)
			}
			change := intrusionPortRecipeChange{Field: args[5], From: nativeOriginal.ActionBefore.Values[args[5]], To: after[args[5]]}
			if recovering {
				change.From, change.To = change.To, change.From
			}
			expected, err := intrusionPortTemplateMutationArgs(*nativeOriginal, change)
			template = err == nil && slices.Equal(args, expected)
			if template {
				templates++
			}
		}
		if !allowed[program+" "+strings.Join(args, " ")] && !batch && !dump && !scalar && !template {
			t.Fatal("nonfixed native operation forbidden", program)
		}
		out, err := RunCommand(ctx, program, args...)
		if err == nil && template && args[5] == "actionflush" && fault != "" && !recovering && !lost {
			// Test-only lost reply AFTER the actual fixed helper completed its
			// single SET+GET. Never inject an error before the real operation.
			lost = true
			return "", errors.New("owned test-only completed template reply lost")
		}
		return out, err
	}
	input := func(ctx context.Context, body []byte, program string, args ...string) (string, error) {
		check := slices.Equal(args, []string{"-c", "-f", "-"})
		if program != "/usr/sbin/nft" || !check && !slices.Equal(args, []string{"-f", "-"}) || len(body) == 0 || len(body) > 4096 {
			t.Fatal("unknown native input operation")
		}
		lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatal("dual stack exact two-handle batch required")
		}
		for _, line := range lines {
			if !strings.HasPrefix(line, "replace rule inet f2b-table f2b-chain handle ") || !strings.Contains(line, "tcp dport { 2882 }") {
				t.Fatal("non-owned input operation forbidden")
			}
		}
		if check {
			checks++
		} else {
			applies++
		}
		return runCommandInput(ctx, body, program, args...)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: filepath.Join(base, "security"), Run: run, RunInput: input})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := core.ID() // Explicit private fixture queue identity, not a real queue receipt.
	ctx = context.WithValue(ctx, intrusionJobContextKey{}, id)
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if recoveryOnly {
		p, raw, err := s.intrusionJournalPending()
		if err != nil || p.Action != "install" || !core.ValidID(os.Getenv("PANEL_OWNED_INTRUSION_EXPECTED_ID")) || p.ID != os.Getenv("PANEL_OWNED_INTRUSION_EXPECTED_ID") || hardeningJournalDigest(raw) != os.Getenv("PANEL_OWNED_INTRUSION_EXPECTED_SHA256") || p.ProcessBefore != pid {
			t.Fatal("independent recovery lacks complete original forward authority", err)
		}
		for _, file := range p.Files {
			if file.Before.Exists {
				t.Fatal("independent recovery is not the new owned install")
			}
		}
		nativeOriginal = &p
		live, err := s.readIntrusionTransactionRuntime(ctx, lock, p, raw)
		after, recipeErr := intrusionPortRecipeTarget(p)
		if err != nil || recipeErr != nil || live.Recipe.Values["actionstart"] != after["actionstart"] || live.Recipe.Values["actionflush"] != after["actionflush"] || live.Recipe.Values["port"] != "22" || !slices.Equal(live.KernelScopePorts, []int{22}) {
			t.Fatal("separate recovery did not observe actual unknown forward result", err, recipeErr)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		// This is a NEW queue identity and a new process/context, not an
		// extension of the failed forward request's deadline or an auto retry.
		if err := s.recoverIntrusionOperation(ctx, map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
			t.Fatal("independent original-bound actual recovery failed", err)
		}
		if templates != 2 || scalars != 0 || checks != 0 || applies != 0 {
			t.Fatal("independent recovery touched unchanged port/kernel or replayed fields", templates, scalars, checks, applies)
		}
		if _, _, err := s.intrusionJournalPending(); !os.IsNotExist(err) {
			t.Fatal("independent recovery did not close original pending", err)
		}
		inventory, err := s.intrusionJournalInventoryRead()
		if err != nil || !intrusionTerminalMatches(inventory.Records[p.ID], p, raw, "rolled_back", id) {
			t.Fatal("independent recovery has no matching immutable terminal", err)
		}
		if _, _, err := s.intrusionJournalObserveFilesAndTree(ctx, p, "rolled_back"); err != nil {
			t.Fatal(err)
		}
		for _, file := range s.intrusionJournalPaths() {
			if _, err := os.Lstat(file); !os.IsNotExist(err) {
				t.Fatal("independent recovery retained a newly created panel file", err)
			}
		}
		current, err := s.readIntrusionMutationRuntime(ctx)
		if err != nil || current.Process != pid || !slices.Equal(current.Policy.Ports, []int{22}) || current.Policy.MaxMatches != 5 || len(current.Bans) != 2 {
			t.Fatal("independent recovery final real state not proven", err)
		}
		dump, err := s.readIntrusionEffectiveConfiguration(ctx, current, current.Settings)
		if err != nil || dump.Identity != p.EffectiveBefore {
			t.Fatal("independent recovery changed effective filters or other configuration", err)
		}
		proof := map[string]any{"ok": true, "original_id": p.ID, "plan_sha256": hardeningJournalDigest(raw), "lifetime_action": "install", "recovery_job_id": id, "recovery_only_process": true, "completed_template_reply_deliberately_lost_in_forward_process": true, "template_sets": templates, "scalar_sets": scalars, "nft_checks": checks, "nft_applies": applies, "terminal_state": "rolled_back", "journal_match": current.JournalMatch, "server_pid": pid, "max_matches": 5, "effective_identity": dump.Identity, "declared_isolated_unit_pid_adapter": true, "normal_program_or_store_acceptance": false, "SSH_authentication_journald_journey": false}
		encoded, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("OWNED_INTRUSION_TRANSACTION:" + base64.StdEncoding.EncodeToString(encoded))
		return
	}
	action := "update"
	var requested map[string]any
	if mode := os.Getenv("PANEL_OWNED_INTRUSION_LIFETIME"); mode == "install" {
		action = "install"
		requested = map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
		for _, file := range s.intrusionJournalPaths() {
			if _, err := os.Lstat(file); !os.IsNotExist(err) {
				t.Fatal("native fresh install requires all three panel files absent", err)
			}
		}
	} else if mode != "" {
		t.Fatal("unknown owned lifetime fixture")
	}
	p, raw, err := s.intrusionPrepareOperation(ctx, lock, action, requested)
	if err != nil {
		t.Fatal("native complete BEFORE prepare failed", err)
	}
	if p.ID != id || p.ProcessBefore != pid || !slices.Equal(p.BeforePolicy.Ports, []int{22}) || !slices.Equal(p.TargetPorts, []int{2882}) || len(p.BansBefore) != 2 || p.KernelState != "rules_observed" {
		t.Fatal("native complete original scope not proven")
	}
	if action == "install" {
		if p.InstallBeforeSettings["max_retry"] != 5 || p.InstallBeforeSettings["find_time_minutes"] != 10 || p.InstallBeforeSettings["ban_time_minutes"] != 60 {
			t.Fatal("native fresh install did not capture real original limits")
		}
		for _, file := range p.Files {
			if file.Before.Exists {
				t.Fatal("native fresh installation fabricated old panel file")
			}
		}
		manifest, err := intrusionJournalManifest(p.Files[1].After)
		if err != nil || manifest.InstalledAt != p.StartedAt {
			t.Fatal("native fresh installation timestamp not original actual prepare", err)
		}
	}
	nativeOriginal = &p
	state, recoveryJob := "committed", ""
	ports := []int{2882}
	err = s.intrusionJournalAdvance(ctx, lock, p, raw, "committed", "")
	if fault == "" {
		if err != nil || scalars != 1 || templates != 2 || checks != 1 || applies != 1 {
			t.Fatal("native transaction failed, replayed or skipped operations", err, scalars, templates, checks, applies)
		}
	} else {
		if err == nil || !lost || scalars != 0 || templates != 2 || checks != 0 || applies != 0 {
			t.Fatal("actual lost reply did not stop before port or nft", err, lost, scalars, templates, checks, applies)
		}
		_, pending, pendingErr := s.intrusionJournalPending()
		inventory, inventoryErr := s.intrusionJournalInventoryRead()
		if pendingErr != nil || inventoryErr != nil || !bytes.Equal(pending, raw) || len(inventory.Records) != 0 {
			t.Fatal("actual unknown result lost original or invented success", pendingErr, inventoryErr)
		}
		live, err := s.readIntrusionTransactionRuntime(ctx, lock, p, raw)
		after, recipeErr := intrusionPortRecipeTarget(p)
		if err != nil || recipeErr != nil || live.Recipe.Values["actionstart"] != after["actionstart"] || live.Recipe.Values["actionflush"] != after["actionflush"] || live.Recipe.Values["port"] != "22" || !slices.Equal(live.KernelScopePorts, []int{22}) {
			t.Fatal("fault did not actually mutate both templates and preserve port/kernel", err, recipeErr)
		}
		if phase == "forward" {
			proof := map[string]any{"ok": true, "operation_committed": false, "terminal_state": "pending", "original_id": p.ID, "plan_sha256": hardeningJournalDigest(raw), "lifetime_action": "install", "completed_template_reply_deliberately_lost": true, "template_sets": templates, "scalar_sets": scalars, "nft_checks": checks, "nft_applies": applies, "server_pid": pid, "normal_program_or_store_acceptance": false, "SSH_authentication_journald_journey": false}
			encoded, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("OWNED_INTRUSION_FORWARD:" + base64.StdEncoding.EncodeToString(encoded))
			return
		}
		if err = lock.Close(); err != nil {
			t.Fatal(err)
		}
		recovering = true
		recoveryJob = core.ID()
		if err = s.recoverIntrusionOperation(context.WithValue(ctx, intrusionJobContextKey{}, recoveryJob), map[string]any{"transaction_id": id, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
			t.Fatal("actual separate original-bound recovery failed", err)
		}
		lock, err = s.intrusionMutationLock()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		state, ports = "rolled_back", []int{22}
		if scalars != 0 || templates != 4 || checks != 0 || applies != 0 {
			t.Fatal("recovery touched unchanged port/kernel or replayed templates", scalars, templates, checks, applies)
		}
		for _, file := range s.intrusionJournalPaths() {
			if _, err := os.Lstat(file); !os.IsNotExist(err) {
				t.Fatal("recovery retained a new panel file", err)
			}
		}
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil || !intrusionTerminalMatches(inventory.Records[id], p, raw, state, recoveryJob) {
		t.Fatal("native immutable terminal not proven", err)
	}
	if _, _, err = s.intrusionJournalPending(); !os.IsNotExist(err) {
		t.Fatal("native transaction pending latch not closed", err)
	}
	if _, _, err = s.intrusionJournalObserveFilesAndTree(ctx, p, state); err != nil {
		t.Fatal("native committed files not proven", err)
	}
	current, err := s.readIntrusionMutationRuntime(ctx)
	if err != nil || current.Process != pid || !slices.Equal(current.Policy.Ports, ports) || current.Policy.MaxMatches != 5 || len(current.Bans) != 2 {
		t.Fatal("native final runtime not proven", err)
	}
	dump, err := s.readIntrusionEffectiveConfiguration(ctx, current, current.Settings)
	if err != nil || dump.Identity != p.EffectiveBefore {
		t.Fatal("native complete effective config drift", err)
	}
	proof := map[string]any{"ok": true, "original_id": id, "plan_sha256": hardeningJournalDigest(raw), "scalar_sets": scalars, "template_sets": templates, "nft_checks": checks, "nft_applies": applies, "terminal_state": "committed", "journal_match": current.JournalMatch, "server_pid": pid, "max_matches": current.Policy.MaxMatches, "effective_identity": dump.Identity, "declared_isolated_unit_pid_adapter": true, "normal_program_or_store_acceptance": false, "SSH_authentication_journald_journey": false}
	proof["lifetime_action"] = action
	proof["terminal_state"] = state
	proof["recovery_job_id"] = recoveryJob
	proof["completed_template_reply_deliberately_lost"] = lost
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_TRANSACTION:" + base64.StdEncoding.EncodeToString(encoded))
}
