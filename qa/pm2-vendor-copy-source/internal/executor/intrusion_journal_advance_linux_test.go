//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

type intrusionAdvanceDriver struct {
	Scalars                           []intrusionScalarChange
	Templates                         []intrusionPortRecipeChange
	LostTemplateField                 string
	Checks, Applies                   int
	KernelPorts                       []int
	LostScalar, LostKernel, FailCheck bool
}

func intrusionAdvanceFixture(t *testing.T) (*Service, *os.File, intrusionJournalPlan, []byte, *intrusionAdvanceDriver, map[string]string) {
	return intrusionAdvanceFixtureWithSetup(t, nil)
}

func intrusionAdvanceFixtureWithSetup(t *testing.T, setup func(*Service, *intrusionJournalPlan)) (*Service, *os.File, intrusionJournalPlan, []byte, *intrusionAdvanceDriver, map[string]string) {
	t.Helper()
	s, answers, lock, p, raw := intrusionTerminalFixtureWithSetup(t, "rolled_back", setup)
	d := &intrusionAdvanceDriver{KernelPorts: []int{22}}
	run := s.Config.Run
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/python3" && len(args) == 13 && args[3] == intrusionPortTemplateMutationScript {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("template lacks bounded deadline")
			}
			fromPolicy, toPolicy := p.BeforePolicy, p.BeforePolicy
			var err error
			fromPolicy.Ports, err = intrusionPortList(args[10])
			if err != nil {
				t.Fatal(err)
			}
			toPolicy.Ports, err = intrusionPortList(args[11])
			if err != nil {
				t.Fatal(err)
			}
			fromValues, err := intrusionStockActionValues(fromPolicy, p.ActionBefore.Values["nftables"], p.ActionBefore.Values["chain"])
			if err != nil {
				t.Fatal(err)
			}
			toValues, err := intrusionStockActionValues(toPolicy, p.ActionBefore.Values["nftables"], p.ActionBefore.Values["chain"])
			if err != nil {
				t.Fatal(err)
			}
			change := intrusionPortRecipeChange{Field: args[5], From: fromValues[args[5]], To: toValues[args[5]]}
			expected, err := intrusionPortTemplateMutationArgs(p, change)
			if err != nil || !slices.Equal(args, expected) {
				t.Fatal("unexpected typed template actuator", err)
			}
			var recipe intrusionActionRecipe
			if err := json.Unmarshal([]byte(answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"]), &recipe); err != nil {
				t.Fatal(err)
			}
			if recipe.Values[change.Field] != change.From {
				t.Fatal("fresh template CAS not matched")
			}
			d.Templates = append(d.Templates, change)
			recipe.Values[change.Field] = change.To
			answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionRecipeJSON(recipe)
			if change.Field == "actionstart" {
				answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = change.To + "\n"
			}
			if d.LostTemplateField == change.Field {
				return "", errors.New("private lost template sentinel")
			}
			receipt, _ := json.Marshal(intrusionPortTemplateReceipt{Format: 1, PID: p.ProcessBefore, StartTicks: p.ProcessStartBefore, Field: change.Field, Action: p.BeforePolicy.Action, FromSHA256: core.Hash(change.From), ToSHA256: core.Hash(change.To), Applied: true})
			return string(receipt) + "\n", nil
		}
		if name != "/usr/bin/python3" || len(args) != 10 || args[3] != intrusionScalarMutationScript {
			return run(ctx, name, args...)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("scalar lacks bounded deadline")
		}
		change := intrusionScalarChange{Key: args[5], From: args[7], To: args[8]}
		expected, err := intrusionScalarMutationArgs(p.ProcessBefore, p.ProcessStartBefore, p.BeforePolicy.Action, change)
		if err != nil || !slices.Equal(args, expected) {
			t.Fatal("unexpected actuator", err)
		}
		key := "/usr/bin/fail2ban-client get sshd " + change.Key
		if change.Key == "port" {
			key = "/usr/bin/fail2ban-client get sshd action nftables port"
		}
		current := strings.TrimSuffix(answers[key], "\n")
		if change.From != current {
			t.Fatal("fresh scalar CAS not matched")
		}
		d.Scalars = append(d.Scalars, change)
		answers[key] = change.To + "\n"
		if change.Key == "port" {
			// Match actual upstream behavior: SET port does NOT regenerate
			// actionstart/actionflush. Those require their own verified SETs.
			var recipe intrusionActionRecipe
			if err := json.Unmarshal([]byte(answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"]), &recipe); err != nil {
				t.Fatal(err)
			}
			recipe.Values["port"] = change.To
			answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionRecipeJSON(recipe)
		}
		if d.LostScalar {
			return "", errors.New("private lost reply sentinel")
		}
		receipt, _ := json.Marshal(intrusionScalarMutationReceipt{Format: 1, PID: p.ProcessBefore, StartTicks: p.ProcessStartBefore, Field: change.Key, Action: args[6], From: change.From, To: change.To, Applied: true})
		return string(receipt) + "\n", nil
	}
	s.Config.RunInput = func(ctx context.Context, input []byte, name string, args ...string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("nft lacks bounded deadline")
		}
		check := slices.Equal(args, []string{"-c", "-f", "-"})
		if name != "/usr/sbin/nft" || !check && !slices.Equal(args, []string{"-f", "-"}) {
			t.Fatal("unknown input actuator", name, args)
		}
		ports, err := intrusionPortList(answers["/usr/bin/fail2ban-client get sshd action nftables port"])
		if err != nil {
			t.Fatal(err)
		}
		policy := p.BeforePolicy
		policy.Ports = d.KernelPorts
		plan, err := planIntrusionNftPortChange([]byte(answers["/usr/sbin/nft -j list table inet f2b-table"]), intrusionPolicyScope(policy, nil), ports)
		if err != nil || string(input) != strings.Join(plan.Statements, "") || len(plan.Statements) != 1 {
			t.Fatal("kernel input was not freshly derived bounded owned-rule plan", err)
		}
		if check {
			d.Checks++
			if d.FailCheck {
				return "", errors.New("private invalid batch sentinel")
			}
			return "", nil
		}
		d.Applies++
		d.KernelPorts = slices.Clone(ports)
		answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, ports)
		if d.LostKernel {
			return "", errors.New("private lost nft sentinel")
		}
		return "", nil
	}
	return s, lock, p, raw, d, answers
}

func TestIntrusionJournalAdvanceCommitsWithOneScalarAndOneAtomicOwnedRuleBatch(t *testing.T) {
	s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
	if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	if len(d.Scalars) != 1 || len(d.Templates) != 2 || d.Scalars[0] != (intrusionScalarChange{Key: "port", From: "22", To: "2882"}) || d.Checks != 1 || d.Applies != 1 {
		t.Fatal("unexpected operation cardinality", d)
	}
	if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original not closed", err)
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil || !intrusionTerminalMatches(inventory.Records[p.ID], p, raw, "committed", "") {
		t.Fatal("actual commit has no exact immutable receipt", err)
	}
}

func TestIntrusionJournalAdvanceUnknownScalarOrKernelStopsWithoutRetryThenExplicitlyRestores(t *testing.T) {
	for _, kind := range []string{"lost-scalar", "failed-nft-check", "lost-nft"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			d.LostScalar, d.FailCheck, d.LostKernel = kind == "lost-scalar", kind == "failed-nft-check", kind == "lost-nft"
			if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err == nil || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("unknown outcome accepted or private error leaked", err)
			}
			if len(d.Scalars) != 1 || len(d.Templates) != 2 || d.Applies > 1 || d.Checks > 1 || kind == "lost-scalar" && d.Checks != 0 || kind == "failed-nft-check" && d.Applies != 0 {
				t.Fatal("unknown write implicitly retried or advanced", d)
			}
			_, current, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(current, raw) {
				t.Fatal("unknown outcome lost original authority", err)
			}
			if inventory, err := s.intrusionJournalInventoryRead(); err != nil || len(inventory.Records) != 0 {
				t.Fatal("unknown outcome published success", err)
			}
			d.LostScalar, d.FailCheck, d.LostKernel = false, false, false
			lock.Close() // A separate explicit recovery must acquire the named lock.
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, core.ID())
			if err := s.recoverIntrusionOperation(ctx, map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
				t.Fatal("explicit original recovery failed", err)
			}
			if len(d.Scalars) != 2 || len(d.Templates) != 4 || d.Scalars[1] != (intrusionScalarChange{Key: "port", From: "2882", To: "22"}) {
				t.Fatal("recovery replayed original forward write", d)
			}
			if _, _, err := s.intrusionJournalObserveFilesAndTree(context.Background(), p, "rolled_back"); err != nil {
				t.Fatal("recovery files differ original", err)
			}
			inventory, err := s.intrusionJournalInventoryRead()
			if err != nil || inventory.Records[p.ID].State != "rolled_back" || inventory.Records[p.ID].PlanSHA256 != hardeningJournalDigest(raw) || inventory.Records[p.ID].RecoveryJobID == "" {
				t.Fatal("explicit recovery lacks original bound immutable record", err)
			}
		})
	}
}

func TestIntrusionJournalAdvanceNeverMutatesAnAlreadyCommittedOriginal(t *testing.T) {
	s2, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
	if err := s2.intrusionJournalWriteFile(context.Background(), lock, p, raw, 0, "committed"); err != nil {
		t.Fatal(err)
	}
	if err := s2.intrusionJournalWriteScalars(context.Background(), lock, p, raw, "committed"); err != nil {
		t.Fatal(err)
	}
	if err := s2.intrusionJournalWriteKernel(context.Background(), lock, p, raw, "committed"); err != nil {
		t.Fatal(err)
	}
	for _, slot := range []int{2, 1} {
		if err := s2.intrusionJournalWriteFile(context.Background(), lock, p, raw, slot, "committed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s2.intrusionJournalWriteTerminal(context.Background(), lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	scalars, templates, checks, applies := len(d.Scalars), len(d.Templates), d.Checks, d.Applies
	recovery := core.ID()
	if err := s2.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, recovery), lock, p, raw, "rolled_back", recovery); err == nil {
		t.Fatal("committed original rolled back")
	}
	if err := s2.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	if len(d.Scalars) != scalars || len(d.Templates) != templates || d.Checks != checks || d.Applies != applies {
		t.Fatal("terminal close replayed system writes")
	}
}

func TestIntrusionJournalPrepareBindsRealObservedStateAndOriginalQueueJobBeforeMutation(t *testing.T) {
	s, _, lock, _, _ := intrusionTerminalFixture(t, "rolled_back")
	if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
		t.Fatal(err)
	} // Isolated fixture setup, not runtime recovery.
	id := core.ID()
	ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, id)
	p, raw, err := s.intrusionPrepareOperation(ctx, lock, "update", nil)
	if err != nil || p.ID != id || p.ProcessBefore != "123" || len(raw) == 0 || p.EffectiveBefore == strings.Repeat("a", 64) || !slices.Equal(p.TargetPorts, []int{2882}) {
		t.Fatal(p.ID, err)
	}
	if _, _, err := s.intrusionJournalObserveFilesAndTree(ctx, p, "rolled_back"); err != nil {
		t.Fatal("prepare mutated files", err)
	}
	if _, _, err := s.intrusionPrepareOperation(ctx, lock, "update", nil); err == nil {
		t.Fatal("prepared original replayed")
	}
}

func TestIntrusionJournalPrepareRejectsMissingJobForeignLimitsAndImplicitUpgrade(t *testing.T) {
	for _, kind := range []string{"missing-job", "foreign-limits", "legacy-configure", "update-settings", "invalid-job"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, lock, _, _ := intrusionTerminalFixture(t, "rolled_back")
			if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, core.ID())
			action := "update"
			var settings map[string]any
			switch kind {
			case "missing-job":
				ctx = context.Background()
			case "invalid-job":
				ctx = context.WithValue(context.Background(), intrusionJobContextKey{}, "not-job")
			case "foreign-limits":
				answers["/usr/bin/fail2ban-client get sshd maxretry"] = "7\n"
			case "legacy-configure":
				action = "configure"
				settings = map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
			case "update-settings":
				settings = map[string]any{"max_retry": 6}
			}
			if _, _, err := s.intrusionPrepareOperation(ctx, lock, action, settings); err == nil {
				t.Fatal("unqualified original prepared")
			}
			if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused prepare created pending", err)
			}
		})
	}
}

func TestIntrusionJournalRecoveryRejectsNewIdentityPartialDigestAndExtraSettings(t *testing.T) {
	for _, kind := range []string{"missing-job", "same-job", "different-original", "short-digest", "upper-digest", "extra-settings"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			lock.Close()
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, core.ID())
			settings := map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}
			switch kind {
			case "missing-job":
				ctx = context.Background()
			case "same-job":
				ctx = context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID)
			case "different-original":
				settings["transaction_id"] = core.ID()
			case "short-digest":
				settings["plan_sha256"] = hardeningJournalDigest(raw)[:12]
			case "upper-digest":
				settings["plan_sha256"] = strings.ToUpper(hardeningJournalDigest(raw))
			case "extra-settings":
				settings["force"] = true
			}
			if err := s.recoverIntrusionOperation(ctx, settings, func(string) {}); err == nil {
				t.Fatal("unbound recovery accepted")
			}
			_, again, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(raw, again) || len(d.Scalars) != 0 || len(d.Templates) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("refused recovery mutated authority", err)
			}
		})
	}
}

func TestIntrusionInputAdapterNeverFallsThroughToHostForCustomRunner(t *testing.T) {
	s := New(Config{SystemRoot: t.TempDir(), Run: func(context.Context, string, ...string) (string, error) { return "", nil }})
	if s.Config.RunInput == nil {
		t.Fatal("missing safe input adapter")
	}
	if _, err := s.Config.RunInput(context.Background(), []byte("forbidden"), "/usr/sbin/nft", "-f", "-"); err == nil {
		t.Fatal("custom fixture fell through to actual host")
	}
}

func TestIntrusionJournalAdvanceFullConfigureKeepsIndependentCapacityAndWritesFourScalarsOnlyOnce(t *testing.T) {
	s, lock, p, raw, d, answers := intrusionAdvanceFixtureWithSetup(t, func(s *Service, p *intrusionJournalPlan) {
		manifest, err := intrusionJournalManifest(p.Files[1].Before)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Version = intrusionTransactionVersion
		manifestRaw, err := intrusionJournalEncode(manifest)
		if err != nil {
			t.Fatal(err)
		}
		policyRaw, err := intrusionJournalEncode(p.BeforePolicy)
		if err != nil {
			t.Fatal(err)
		}
		jail, err := renderIntrusionManagedScope(manifest.Settings, p.BeforePolicy)
		if err != nil {
			t.Fatal(err)
		}
		for i, data := range [][]byte{[]byte(jail), manifestRaw, policyRaw} {
			mode := os.FileMode(0600)
			if i == 0 {
				mode = 0644
			}
			if err := os.WriteFile(s.intrusionJournalPaths()[i], data, mode); err != nil {
				t.Fatal(err)
			}
		}
		files, err := s.intrusionJournalCurrentFiles()
		if err != nil {
			t.Fatal(err)
		}
		for i := range files {
			p.Files[i].Before = hardeningJournalFromBackup(files[i])
		}
		p.ConfigurationBefore, err = s.readIntrusionConfigurationTree(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		p.Action = "configure"
		p.TargetSettings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
	})
	if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	expected := []intrusionScalarChange{{Key: "maxretry", From: "5", To: "6"}, {Key: "findtime", From: "600", To: "660"}, {Key: "bantime", From: "3600", To: "3660"}, {Key: "port", From: "22", To: "2882"}}
	if !slices.Equal(d.Scalars, expected) || len(d.Templates) != 2 || d.Checks != 1 || d.Applies != 1 {
		t.Fatal("unbounded, repeated or skipped real step", d)
	}
	if answers["/usr/bin/fail2ban-client get sshd maxmatches"] != "5\n" {
		t.Fatal("matching capacity reset with retry count")
	}
	// This private transaction model is not a published normal 1.1 handler.
	// Its strict, versioned canonical parser must check the derived record;
	// the still-1.0 normal catalog must KEEP rejecting premature 1.1 claims.
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := intrusionJournalManifest(hardeningJournalFromBackup(files[1]))
	if err != nil || manifest.Version != intrusionTransactionVersion {
		t.Fatal(manifest.Version, err)
	}
}

func TestIntrusionJournalAdvanceRequiresOriginalQueueContextBeforeAnyWrite(t *testing.T) {
	for _, kind := range []string{"missing", "different"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			ctx := context.Background()
			if kind == "different" {
				ctx = context.WithValue(ctx, intrusionJobContextKey{}, core.ID())
			}
			if err := s.intrusionJournalAdvance(ctx, lock, p, raw, "committed", ""); err == nil {
				t.Fatal("unbound queue context reached writer")
			}
			if _, _, err := s.intrusionJournalObserveFilesAndTree(ctx, p, "rolled_back"); err != nil {
				t.Fatal(err)
			}
			if len(d.Scalars) != 0 || len(d.Templates) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("unbound context mutated runtime")
			}
		})
	}
}

func TestIntrusionPortOnlySetterDoesNotRegenerateLiteralTemplatesOrQualifyKernelWrites(t *testing.T) {
	s, lock, p, raw, d, answers := intrusionAdvanceFixture(t)
	args, err := intrusionScalarMutationArgs(p.ProcessBefore, p.ProcessStartBefore, p.BeforePolicy.Action, intrusionScalarChange{Key: "port", From: "22", To: "2882"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = s.Config.Run(ctx, "/usr/bin/python3", args...); err != nil {
		t.Fatal(err)
	}
	var recipe intrusionActionRecipe
	if err = json.Unmarshal([]byte(answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"]), &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.Values["port"] != "2882" || recipe.Values["actionstart"] != p.ActionBefore.Values["actionstart"] || recipe.Values["actionflush"] != p.ActionBefore.Values["actionflush"] || len(d.Templates) != 0 {
		t.Fatal("fixture incorrectly regenerated templates after SETport")
	}
	live, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw)
	if err != nil {
		t.Fatal("guarded original cannot observe actual port-only interruption", err)
	}
	next, err := intrusionPortRecipeChanges(p, live.Recipe, "committed")
	if err != nil || len(next.Changes) != 2 {
		t.Fatal("missing literal template operations not detected", err)
	}
	if _, err := intrusionJournalCurrentNftPlan(p, live, "committed"); err == nil {
		t.Fatal("incomplete action literals authorized a kernel batch")
	}
	if err := intrusionJournalRuntimeAt(p, live, "committed"); err == nil {
		t.Fatal("incomplete action literals reported committed")
	}
}

func TestIntrusionPortOnlyWriterSharesOnlyImmediatelyUnchangedCompleteBoundary(t *testing.T) {
	s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
	run := s.Config.Run
	dumps, firstTemplate := 0, false
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/python3" && len(args) == 4 && args[3] == intrusionConfigurationDumpScript {
			dumps++
		}
		if !firstTemplate && name == "/usr/bin/python3" && len(args) == 13 && args[3] == intrusionPortTemplateMutationScript {
			firstTemplate = true
			if dumps != 1 || len(d.Scalars) != 0 || len(d.Templates) != 0 {
				t.Fatal("first template lacks one immediate complete no-write boundary", dumps, d)
			}
		}
		return run(ctx, name, args...)
	}
	if err := s.intrusionJournalWriteScalars(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed"); err != nil {
		t.Fatal(err)
	}
	if !firstTemplate || len(d.Templates) != 2 || len(d.Scalars) != 1 || dumps != 3 || d.Checks != 0 || d.Applies != 0 {
		t.Fatal("later actual writes skipped their own complete boundary or changed kernel", dumps, d)
	}
	if _, pending, err := s.intrusionJournalPending(); err != nil || !bytes.Equal(raw, pending) {
		t.Fatal("port-only path changed original authority", err)
	}
}

func TestIntrusionLostTemplateReplyStopsBeforePortAndExplicitlyRestoresOnlyChangedFields(t *testing.T) {
	for _, field := range []string{"actionstart", "actionflush"} {
		t.Run(field, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			d.LostTemplateField = field
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID)
			if err := s.intrusionJournalAdvance(ctx, lock, p, raw, "committed", ""); err == nil || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("lost template outcome accepted or leaked", err)
			}
			changed := 1
			if field == "actionflush" {
				changed = 2
			}
			if len(d.Templates) != changed || len(d.Scalars) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("unknown template outcome advanced/retried", len(d.Templates), len(d.Scalars))
			}
			_, again, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("lost template outcome lost original record", err)
			}
			inventory, err := s.intrusionJournalInventoryRead()
			if err != nil || len(inventory.Records) != 0 {
				t.Fatal("lost template outcome published success", err)
			}
			d.LostTemplateField = ""
			lock.Close()
			recovery := core.ID()
			ctx = context.WithValue(context.Background(), intrusionJobContextKey{}, recovery)
			if err := s.recoverIntrusionOperation(ctx, map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
				t.Fatal("explicit partial-template original recovery failed", err)
			}
			if len(d.Templates) != 2*changed || len(d.Scalars) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("recovery rewrote untouched port/kernel or repeated fields")
			}
			for _, change := range d.Templates[changed:] {
				if change.To != p.ActionBefore.Values[change.Field] {
					t.Fatal("recovery did not restore exact source-derived original literal")
				}
			}
			inventory, err = s.intrusionJournalInventoryRead()
			if err != nil || !intrusionTerminalMatches(inventory.Records[p.ID], p, raw, "rolled_back", recovery) {
				t.Fatal("partial-template recovery lacks immutable original closure", err)
			}
			if _, _, err = s.intrusionJournalObserveFilesAndTree(context.Background(), p, "rolled_back"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
