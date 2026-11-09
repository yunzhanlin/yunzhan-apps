//go:build linux

package executor

import (
	"bytes"
	"context"
	"maps"
	"os"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func hardeningRecoverySettings(plan hardeningJournalPlan, raw []byte) map[string]any {
	return map[string]any{"transaction_id": plan.ID, "sha256": hardeningJournalDigest(raw), "confirm": plan.ID}
}

func hardeningStageCandidate(t *testing.T, f *hardeningFixture, plan hardeningJournalPlan, phase string) {
	t.Helper()
	paths := f.s.hardeningJournalPaths()
	if phase == "prepared" {
		return
	}
	file := plan.Files[0].After
	if err := atomicWriteWithOwner(paths[0], file.Data, os.FileMode(file.Mode), file.Owner); err != nil {
		t.Fatal(err)
	}
	if phase == "config" {
		return
	}
	maps.Copy(f.values, plan.AfterKernel)
	if phase == "kernel" {
		return
	}
	file = plan.Files[2].After
	if err := atomicWriteWithOwner(paths[2], file.Data, os.FileMode(file.Mode), file.Owner); err != nil {
		t.Fatal(err)
	}
}

func TestHardeningJournalExplicitRecoveryRestoresOnlyCapturedOriginalMixedState(t *testing.T) {
	for _, phase := range []string{"prepared", "config", "kernel", "manifest"} {
		t.Run(phase, func(t *testing.T) {
			f, p := hardeningJournalFixturePlan(t, "baseline", "strict")
			raw, err := f.s.hardeningJournalPrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			hardeningStageCandidate(t, f, p, phase)
			job := core.ID()
			ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, job)
			if err = f.s.recoverHardeningOperation(ctx, hardeningRecoverySettings(p, raw), func(string) {}); err != nil {
				t.Fatal(err)
			}
			if err = f.s.hardeningJournalVerifyState(ctx, p, "rolled_back"); err != nil {
				t.Fatal(err)
			}
			inventory, err := f.s.hardeningJournalInventoryRead()
			if err != nil {
				t.Fatal(err)
			}
			terminal := inventory.Records[p.ID]
			if terminal.State != "rolled_back" || terminal.RecoveryJobID != job || terminal.PlanSHA256 != hardeningJournalDigest(raw) {
				t.Fatal("original/recovery identities lost")
			}
			writes := f.writes
			before := hardeningGuardTree(t, f.s.Config.SystemRoot)
			if err = f.s.recoverHardeningOperation(ctx, hardeningRecoverySettings(p, raw), func(string) {}); err != nil {
				t.Fatal(err)
			}
			if writes != f.writes || !reflect.DeepEqual(before, hardeningGuardTree(t, f.s.Config.SystemRoot)) {
				t.Fatal("closed compensation replay mutated original state")
			}
		})
	}
}

func TestHardeningJournalCommittedBeforePendingRemovalOnlyFinalizesMetadata(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "baseline", "strict")
	raw, err := f.s.hardeningJournalPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	hardeningStageCandidate(t, f, p, "manifest")
	if err = f.s.hardeningJournalWriteTerminal(p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	writes := f.writes
	ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, core.ID())
	if err = f.s.recoverHardeningOperation(ctx, hardeningRecoverySettings(p, raw), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if f.writes != writes {
		t.Fatal("committed original was compensated again")
	}
	if err = f.s.hardeningJournalVerifyState(ctx, p, "committed"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.hardeningJournalPending(); !os.IsNotExist(err) {
		t.Fatal("metadata finish did not close pending", err)
	}
}

func TestHardeningJournalRecoveryForeignAuthorityRefusesBeforeWrites(t *testing.T) {
	for _, mode := range []string{"wrong-digest", "wrong-confirm", "foreign-kernel", "foreign-config"} {
		t.Run(mode, func(t *testing.T) {
			f, p := hardeningJournalFixturePlan(t, "baseline", "strict")
			raw, err := f.s.hardeningJournalPrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			settings := hardeningRecoverySettings(p, raw)
			hardeningStageCandidate(t, f, p, "kernel")
			switch mode {
			case "wrong-digest":
				settings["sha256"] = core.Hash("foreign")
			case "wrong-confirm":
				settings["confirm"] = core.ID()
			case "foreign-kernel":
				f.values["kernel.yama.ptrace_scope"] = "2"
			case "foreign-config":
				path := f.s.hardeningJournalPaths()[0]
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, append(data, []byte("# independent external edit\n")...), 0644); err != nil {
					t.Fatal(err)
				}
			}
			before := hardeningGuardTree(t, f.s.Config.SystemRoot)
			kernel := maps.Clone(f.values)
			writes := f.writes
			if err = f.s.recoverHardeningOperation(context.WithValue(context.Background(), hardeningJobContextKey{}, core.ID()), settings, func(string) {}); err == nil {
				t.Fatal("foreign authority recovered", mode)
			}
			if f.writes != writes || !maps.Equal(kernel, f.values) || !reflect.DeepEqual(before, hardeningGuardTree(t, f.s.Config.SystemRoot)) {
				t.Fatal("foreign authority/kernel/files repaired", mode)
			}
		})
	}
}

func TestHardeningJournalPartialCompensationRetainsOriginalPlanAndContinuesWithoutNewIdentity(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "baseline", "strict")
	raw, err := f.s.hardeningJournalPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	hardeningStageCandidate(t, f, p, "kernel")
	f.failWrite = "kernel.unprivileged_bpf_disabled"
	ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, core.ID())
	if err = f.s.recoverHardeningOperation(ctx, hardeningRecoverySettings(p, raw), func(string) {}); err == nil {
		t.Fatal("partial compensation claimed success")
	}
	got, again, err := f.s.hardeningJournalPending()
	if err != nil || got.ID != p.ID || !bytes.Equal(raw, again) {
		t.Fatal("partial compensation lost original identity", err)
	}
	if err = f.s.recoverHardeningOperation(ctx, hardeningRecoverySettings(p, raw), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.hardeningJournalVerifyState(ctx, p, "rolled_back"); err != nil {
		t.Fatal(err)
	}
}

func TestHardeningJournalOriginalJobReceiptNeverReplaysCommittedMutationOrChangedPayload(t *testing.T) {
	f := newHardeningFixture(t)
	id := core.ID()
	ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, id)
	if err := f.s.applyHardening(ctx, map[string]any{"profile": "baseline"}, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	before := hardeningGuardTree(t, f.s.Config.SystemRoot)
	writes := f.writes
	if err := f.s.applyHardening(ctx, map[string]any{"profile": "baseline"}, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.applyHardening(ctx, map[string]any{"profile": "strict"}, true, func(string) {}); err == nil {
		t.Fatal("original ID accepted changed payload")
	}
	if f.writes != writes || !reflect.DeepEqual(before, hardeningGuardTree(t, f.s.Config.SystemRoot)) {
		t.Fatal("original receipt replay changed kernel/files")
	}
}
