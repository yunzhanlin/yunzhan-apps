//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHardeningInspectionIsReadOnlyAndShowsOriginalsDriftAndHistory(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	before, err := f.s.hardeningJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	writes := f.writes
	out, err := f.s.inspectHardening(context.Background())
	if err != nil || !out.Healthy || !out.OriginalsComplete || !out.ConfigMatches || len(out.Parameters) != len(hardeningValues("strict")) || len(out.History) != 1 || out.Pending != nil {
		t.Fatal(out, err)
	}
	for _, row := range out.Parameters {
		if row.Managed && (!row.OriginalKnown || row.Original != "0" || row.Actual != row.Target || row.Drift) {
			t.Fatal(row)
		}
	}
	after, err := f.s.hardeningJournalCurrentFiles()
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if !hardeningBackupSame(before[i], after[i]) {
			t.Fatal("read modified files")
		}
	}
	if writes != f.writes {
		t.Fatal("inspection wrote kernel")
	}
	f.values["kernel.dmesg_restrict"] = "0"
	out, err = f.s.inspectHardening(context.Background())
	if err != nil || out.Healthy || f.writes != writes {
		t.Fatal(out, err)
	}
	if status := f.s.softwareStatus(context.Background(), "system-hardening"); !status.Installed || status.Healthy || status.StateUnknown {
		t.Fatal(status)
	}
}

func TestHardeningInspectionPendingBlocksHealthyWithoutPerformingRecovery(t *testing.T) {
	f, plan := hardeningJournalFixturePlan(t, "baseline", "strict")
	raw, err := f.s.hardeningJournalPrepare(plan)
	if err != nil {
		t.Fatal(err)
	}
	writes := f.writes
	out, err := f.s.inspectHardening(context.Background())
	if err != nil || out.Healthy || out.Pending == nil || out.Pending.ID != plan.ID || out.Pending.SHA256 != hardeningJournalDigest(raw) || !out.Pending.RecoveryPermitted {
		t.Fatal(out, err)
	}
	_, after, err := f.s.hardeningJournalPending()
	if err != nil || !bytes.Equal(raw, after) || writes != f.writes {
		t.Fatal("inspection changed source", err)
	}
	status := f.s.softwareStatus(context.Background(), "system-hardening")
	if status.Healthy || status.StateUnknown {
		t.Fatal(status)
	}
	encoded, _ := json.Marshal(out)
	if bytes.Contains(encoded, []byte(`"before_kernel"`)) || bytes.Contains(encoded, []byte(`"data"`)) || bytes.Contains(encoded, []byte(`"owner"`)) {
		t.Fatal("private journal leaked instead of fixed summary")
	}
}

func TestHardeningInspectionMalformedEvidenceRefusesWithoutRepairOrLockCreation(t *testing.T) {
	for _, kind := range []string{"partial", "public", "linked"} {
		t.Run(kind, func(t *testing.T) {
			f := newHardeningFixture(t)
			p := filepath.Join(f.s.Config.SecurityDir, hardeningPendingName)
			if kind == "linked" {
				if err := os.Symlink("/unreadable-foreign-evidence", p); err != nil {
					t.Fatal(err)
				}
			} else {
				mode := os.FileMode(0600)
				if kind == "public" {
					mode = 0644
				}
				if err := os.WriteFile(p, []byte(`{"format":`), mode); err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.inspectHardening(context.Background()); err == nil {
				t.Fatal("malformed evidence accepted")
			}
			after, err := os.Lstat(p)
			if err != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() {
				t.Fatal("evidence repaired", err)
			}
			if _, err = os.Lstat(filepath.Join(f.s.Config.SecurityDir, "hardening-configuration.lock")); !os.IsNotExist(err) {
				t.Fatal("observation created a lock", err)
			}
			if f.writes != 0 {
				t.Fatal("observation wrote kernel")
			}
		})
	}
}

func TestHardeningInspectionMissingOriginalsIsNotHealthyAndDoesNotGuessDefaults(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	m, err := f.s.readSoftwareManifest("system-hardening")
	if err != nil {
		t.Fatal(err)
	}
	delete(m.Previous, "kernel.dmesg_restrict")
	if err = f.s.writeSoftwareManifest(m); err != nil {
		t.Fatal(err)
	}
	writes := f.writes
	out, err := f.s.inspectHardening(context.Background())
	if err != nil || out.Healthy || out.OriginalsComplete || f.writes != writes {
		t.Fatal(out, err)
	}
	for _, row := range out.Parameters {
		if row.OriginalKnown {
			t.Fatal("incomplete authority was partially guessed", row)
		}
	}
}
