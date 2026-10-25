//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIntrusionWorkspacePendingNeverBecomesInstalledOrHealthy(t *testing.T) {
	for _, stage := range []string{"original", "jail-after", "all-files-after", "committed-pending"} {
		t.Run(stage, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixtureWithSetup(t, func(_ *Service, p *intrusionJournalPlan) { intrusionRemovalPlanSetup(t, p, []int{22}) })
			ctx := context.Background()
			if stage != "original" {
				if err := s.intrusionJournalWriteFile(ctx, lock, p, raw, 0, "committed"); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "all-files-after" || stage == "committed-pending" {
				if err := s.intrusionJournalWriteScalars(ctx, lock, p, raw, "committed"); err != nil {
					t.Fatal(err)
				}
				if err := s.intrusionJournalWriteKernel(ctx, lock, p, raw, "committed"); err != nil {
					t.Fatal(err)
				}
				for _, slot := range []int{2, 1} {
					if err := s.intrusionJournalWriteFile(ctx, lock, p, raw, slot, "committed"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if stage == "committed-pending" {
				if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "committed", ""); err != nil {
					t.Fatal(err)
				}
			}
			lock.Close()
			before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
			counts := []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}
			out, err := s.inspectIntrusionWorkspace(ctx)
			if err != nil || out.StateKnown || out.Current != nil || out.Pending == nil || !out.Pending.RecoveryPermitted || out.Pending.ID != p.ID || out.Pending.SHA256 != hardeningJournalDigest(raw) || !out.Pending.DurationChangesExistingBans {
				t.Fatal("partial lifetime became accepted installed/healthy state", out, err)
			}
			want := "pending"
			history := 0
			if stage == "committed-pending" {
				want = "committed_pending_cleanup"
				history = 1
			}
			if out.Pending.State != want || len(out.History) != history {
				t.Fatal("terminal was confused with cleanup or missing history")
			}
			data, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{`"installed"`, `"healthy"`, `"kernel_before"`, `"bans_before"`, `"dump"`, `"action_before"`, `"configuration_before"`} {
				if bytes.Contains(data, []byte(private)) {
					t.Fatal("private authority or a false current state escaped into pending view", private)
				}
			}
			if !strings.Contains(out.BanDurationSemantics, "到期时间") || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) || !reflect.DeepEqual(counts, []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}) {
				t.Fatal("read-only workspace changed files/runtime or concealed duration effect")
			}
			_, again, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatal("view closed, repaired or replaced original", err)
			}
		})
	}
}

func TestIntrusionWorkspaceSharedObservationCannotGrantMutationOrSurviveReplacement(t *testing.T) {
	for _, kind := range []string{"exclusive-busy", "shared-readers", "named-replacement"} {
		t.Run(kind, func(t *testing.T) {
			s, held, p, raw, _, _ := intrusionAdvanceFixture(t)
			if kind == "exclusive-busy" {
				if view, err := s.intrusionObservationLock(); err == nil {
					if view != nil {
						view.Close()
					}
					t.Fatal("observation bypassed active exclusive transaction")
				}
				return
			}
			held.Close()
			first, err := s.intrusionObservationLock()
			if err != nil || first == nil {
				t.Fatal(err)
			}
			defer first.Close()
			if kind == "shared-readers" {
				if err := s.intrusionJournalRequireLock(first); err == nil {
					t.Fatal("read-only descriptor converted into a mutation lock")
				}
				second, err := s.intrusionObservationLock()
				if err != nil || second == nil {
					t.Fatal("independent read-only observer refused", err)
				}
				defer second.Close()
				if writer, err := s.intrusionMutationLock(); err == nil {
					writer.Close()
					t.Fatal("read-only shared observer granted an independent writer")
				}
				if err := s.intrusionObservationOriginal(first, p, raw); err != nil {
					t.Fatal(err)
				}
			} else {
				name := filepath.Join(s.Config.SecurityDir, intrusionMutationLockName)
				if err := atomicWrite(name, []byte("external replacement\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := s.intrusionObservationOriginal(first, p, raw); err == nil {
					t.Fatal("old descriptor became authority for a new named lock")
				}
				data, err := os.ReadFile(name)
				if err != nil || string(data) != "external replacement\n" {
					t.Fatal("observer repaired replaced lock", err)
				}
			}
		})
	}
}

func TestIntrusionWorkspaceUnknownAuthoritiesNeverReturnAHealthyCurrent(t *testing.T) {
	for _, kind := range []string{"corrupt-pending", "public-pending", "missing-lock", "changed-boot", "changed-daemon", "third-kernel", "source-change", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, _, d, answers := intrusionAdvanceFixture(t)
			lock.Close()
			ctx := context.Background()
			switch kind {
			case "corrupt-pending":
				if err := os.WriteFile(filepath.Join(s.Config.SecurityDir, intrusionPendingName), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-pending":
				if err := os.Chmod(filepath.Join(s.Config.SecurityDir, intrusionPendingName), 0644); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionMutationLockName)); err != nil {
					t.Fatal(err)
				}
			case "changed-boot":
				if err := os.Chmod(s.systemPath("/proc/sys/kernel/random/boot_id"), 0644); err != nil {
					t.Fatal(err)
				} // Only this fake-SystemRoot fixture.
				if err := os.WriteFile(s.systemPath("/proc/sys/kernel/random/boot_id"), []byte("22222222-3333-4444-5555-666666666666\n"), 0444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(s.systemPath("/proc/sys/kernel/random/boot_id"), 0444); err != nil {
					t.Fatal(err)
				}
			case "changed-daemon":
				answers["/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState"] = "MainPID=124\nActiveState=active\n"
			case "third-kernel":
				answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, []int{29999})
			case "source-change":
				if err := os.WriteFile(s.intrusionJournalPaths()[0], append(bytes.Clone(p.Files[0].Before.Data), []byte("# external\n")...), 0644); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
			out, err := s.inspectIntrusionWorkspace(ctx)
			wantError := kind == "corrupt-pending" || kind == "public-pending" || kind == "cancelled"
			if (err != nil) != wantError || out.StateKnown || out.Current != nil || !wantError && (out.Pending == nil || out.Pending.RecoveryPermitted) {
				t.Fatal("unknown source gained current-health or recovery permission", out, err)
			}
			if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) || len(d.Scalars) != 0 || len(d.Templates) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("unknown observation changed authority/runtime")
			}
		})
	}
}

func TestIntrusionWorkspaceReadyReadDoesNotCreateLockArchiveOrRepairSource(t *testing.T) {
	s, _, calls := intrusionInspectionFixture(t)
	before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
	out, err := s.inspectIntrusionWorkspace(context.Background())
	if err != nil || !out.StateKnown || out.Current == nil || !out.Current.Installed || !out.Current.Healthy || out.Pending != nil || len(out.History) != 0 || out.RetainedTemporaries != 0 || *calls != 18 {
		t.Fatal(out, err, *calls)
	}
	if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) {
		t.Fatal("read-only ready view created lock/archive or rewrote configuration")
	}
}
