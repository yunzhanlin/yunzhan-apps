//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func intrusionInstallPlanFixture(t *testing.T) intrusionJournalPlan {
	t.Helper()
	p := intrusionJournalClone(t, intrusionJournalFixture(t))
	p.Action = "install"
	p.InstallBeforeSettings = map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
	p.ConfigurationBefore.Bytes -= p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"].Size
	delete(p.ConfigurationBefore.Entries, "jail.d/panel-intrusion.local")
	for i := range p.Files {
		p.Files[i].Before = hardeningJournalFile{}
	}
	p, err := intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Only files created by these private fake-SystemRoot fixtures are removed.
// No test helper calls the normal installed application's removal operation.
func intrusionInstallFixtureSetup(t *testing.T, s *Service, p *intrusionJournalPlan) {
	t.Helper()
	for i, file := range p.Files {
		if file.Before.Exists {
			if err := os.Remove(s.intrusionJournalPaths()[i]); err != nil {
				t.Fatal(err)
			}
		}
		p.Files[i].Before = hardeningJournalFile{}
	}
	p.Action = "install"
	p.InstallBeforeSettings = map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
	var err error
	p.ConfigurationBefore, err = s.readIntrusionConfigurationTree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntrusionInstallRecordsActualBaseLimitsWithoutSyntheticManifest(t *testing.T) {
	for _, different := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-limits", true: "changed-limits"}[different], func(t *testing.T) {
			p := intrusionInstallPlanFixture(t)
			if different {
				p.TargetSettings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
				var err error
				p, err = intrusionJournalDerive(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err := intrusionJournalEncode(p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := intrusionJournalDecode(raw)
			if err != nil || !reflect.DeepEqual(decoded, p) {
				t.Fatal("original installation authority not canonical", err)
			}
			for _, file := range p.Files {
				if file.Before.Exists || !file.After.Exists {
					t.Fatal("fabricated old app or incomplete target")
				}
			}
			manifest, err := intrusionJournalManifest(p.Files[1].After)
			if err != nil || manifest.InstalledAt != p.StartedAt || manifest.Version != intrusionTransactionVersion {
				t.Fatal("installation copied an invented old timestamp", err)
			}
			before, err := intrusionJournalBeforeSettings(p)
			if err != nil || !maps.Equal(before, p.InstallBeforeSettings) {
				t.Fatal(before, err)
			}
			before["max_retry"] = 7
			again, _ := intrusionJournalEncode(p)
			if !bytes.Equal(raw, again) {
				t.Fatal("returned limits aliased immutable original")
			}
		})
	}
}

func TestIntrusionInstallRejectsOccupiedUnknownOrInventedBeforeState(t *testing.T) {
	for name, change := range map[string]func(*intrusionJournalPlan){
		"occupied-jail":      func(p *intrusionJournalPlan) { p.Files[0].Before = p.Files[0].After },
		"occupied-manifest":  func(p *intrusionJournalPlan) { p.Files[1].Before = p.Files[1].After },
		"occupied-policy":    func(p *intrusionJournalPlan) { p.Files[2].Before = p.Files[2].After },
		"dirty-absence-data": func(p *intrusionJournalPlan) { p.Files[0].Before.Data = []byte("foreign") },
		"dirty-absence-mode": func(p *intrusionJournalPlan) { p.Files[0].Before.Mode = 0644 },
		"missing-limits":     func(p *intrusionJournalPlan) { p.InstallBeforeSettings = nil },
		"partial-limits":     func(p *intrusionJournalPlan) { delete(p.InstallBeforeSettings, "max_retry") },
		"unknown-limit":      func(p *intrusionJournalPlan) { p.InstallBeforeSettings["command"] = 1 },
		"invalid-limit":      func(p *intrusionJournalPlan) { p.InstallBeforeSettings["max_retry"] = 0 },
		"missing-parent":     func(p *intrusionJournalPlan) { delete(p.ConfigurationBefore.Entries, "jail.d") },
		"invented-tree-file": func(p *intrusionJournalPlan) {
			old := intrusionJournalFixture(t).ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
			p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"] = old
			p.ConfigurationBefore.Bytes += old.Size
		},
		"forged-target":     func(p *intrusionJournalPlan) { p.Files[0].After.Data = []byte("foreign") },
		"configure-absence": func(p *intrusionJournalPlan) { p.Action = "configure" },
		"update-absence":    func(p *intrusionJournalPlan) { p.Action = "update" },
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionInstallPlanFixture(t)
			change(&p)
			before, _ := intrusionJournalEncode(p)
			if err := intrusionJournalValidate(p); err == nil {
				t.Fatal("unqualified installation authority accepted")
			}
			after, _ := intrusionJournalEncode(p)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected installation was silently repaired")
			}
		})
	}
	for _, action := range []string{"update", "configure"} {
		p := intrusionJournalFixture(t)
		p.Action = action
		p.InstallBeforeSettings = map[string]int{}
		if _, err := intrusionJournalBeforeSettings(p); err == nil {
			t.Fatal("existing app accepted separate install authority", action)
		}
	}
}

func TestIntrusionInstallAdvanceCommitsThreeNewFilesAndKeepsBaseJail(t *testing.T) {
	for _, different := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-limits", true: "changed-limits"}[different], func(t *testing.T) {
			s, lock, p, raw, d, answers := intrusionAdvanceFixtureWithSetup(t, func(s *Service, p *intrusionJournalPlan) {
				intrusionInstallFixtureSetup(t, s, p)
				if different {
					p.TargetSettings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
				}
			})
			if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err != nil {
				t.Fatal(err)
			}
			wanted := 1
			if different {
				wanted = 4
			}
			if len(d.Scalars) != wanted || len(d.Templates) != 2 || d.Checks != 1 || d.Applies != 1 || answers["/usr/bin/fail2ban-client get sshd maxmatches"] != "5\n" {
				t.Fatal("installation restarted, reset capacity or skipped a fixed step", d)
			}
			if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("committed installation left pending", err)
			}
			inventory, err := s.intrusionJournalInventoryRead()
			if err != nil || inventory.Records[p.ID].State != "committed" || inventory.Records[p.ID].Plan.Action != "install" {
				t.Fatal("installation lacks actual verified immutable terminal", err)
			}
		})
	}
}

func TestIntrusionInstallUnknownOutcomeExplicitlyRestoresOnlyNewPanelFiles(t *testing.T) {
	for _, point := range []string{"scalar", "actionstart", "actionflush", "kernel"} {
		t.Run(point, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixtureWithSetup(t, func(s *Service, p *intrusionJournalPlan) { intrusionInstallFixtureSetup(t, s, p) })
			switch point {
			case "scalar":
				d.LostScalar = true
			case "kernel":
				d.LostKernel = true
			default:
				d.LostTemplateField = point
			}
			if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err == nil {
				t.Fatal("unknown outcome was reported committed")
			}
			_, pending, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(pending, raw) {
				t.Fatal("failure lost or replaced original", err)
			}
			inventory, err := s.intrusionJournalInventoryRead()
			if err != nil || len(inventory.Records) != 0 {
				t.Fatal("failure published success", err)
			}
			d.LostScalar, d.LostKernel, d.LostTemplateField = false, false, ""
			lock.Close()
			job := core.ID()
			if err := s.recoverIntrusionOperation(context.WithValue(context.Background(), intrusionJobContextKey{}, job), map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
				t.Fatal(err)
			}
			for _, file := range s.intrusionJournalPaths() {
				if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("restoration left a newly created panel file", file, err)
				}
			}
			if inventory, err := s.intrusionJournalInventoryRead(); err != nil || inventory.Records[p.ID].State != "rolled_back" || inventory.Records[p.ID].RecoveryJobID != job {
				t.Fatal("explicit installation recovery was not immutable", err)
			}
		})
	}
}

func TestIntrusionInstallPrepareRequiresActualActiveBaseAndThreeAbsentFiles(t *testing.T) {
	for _, kind := range []string{"ready", "missing-job", "occupied-jail", "occupied-manifest", "occupied-policy", "invalid-settings", "inactive-base", "unknown-backend"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, lock, original, _ := intrusionTerminalFixtureWithSetup(t, "rolled_back", func(s *Service, p *intrusionJournalPlan) { intrusionInstallFixtureSetup(t, s, p) })
			// Remove ONLY this fake-SystemRoot fixture's original pending,
			// before testing the real initial prepare entry point.
			if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
				t.Fatal(err)
			}
			job := core.ID()
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, job)
			settings := map[string]any{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
			switch kind {
			case "missing-job":
				ctx = context.Background()
			case "occupied-jail", "occupied-manifest", "occupied-policy":
				slot := map[string]int{"occupied-jail": 0, "occupied-manifest": 1, "occupied-policy": 2}[kind]
				file := original.Files[slot].After
				if err := os.WriteFile(s.intrusionJournalPaths()[slot], file.Data, os.FileMode(file.Mode)); err != nil {
					t.Fatal(err)
				}
			case "invalid-settings":
				settings["command"] = "reload"
			case "inactive-base":
				answers["/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState"] = "MainPID=0\nActiveState=inactive\n"
			case "unknown-backend":
				answers["/usr/bin/fail2ban-client get sshd journalmatch"] = "custom file backend\n"
			}
			before, err := s.intrusionJournalCurrentFiles()
			if err != nil {
				t.Fatal(err)
			}
			p, raw, err := s.intrusionPrepareOperation(ctx, lock, "install", settings)
			if kind == "ready" {
				if err != nil || p.ID != job || p.Action != "install" || len(raw) == 0 || !maps.Equal(p.InstallBeforeSettings, original.InstallBeforeSettings) || p.TargetSettings["max_retry"] != 6 {
					t.Fatal("actual initial preparation failed", p.ID, err)
				}
				if _, _, err := s.intrusionJournalObserveFilesAndTree(ctx, p, "rolled_back"); err != nil {
					t.Fatal("preparation modified panel files", err)
				}
				if _, _, err := s.intrusionPrepareOperation(ctx, lock, "install", settings); err == nil {
					t.Fatal("initial preparation replayed")
				}
			} else {
				if err == nil {
					t.Fatal("unqualified install prepared")
				}
				if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected prepare created authority", err)
				}
			}
			after, err := s.intrusionJournalCurrentFiles()
			if err != nil {
				t.Fatal(err)
			}
			for i := range before {
				if !hardeningBackupSame(before[i], after[i]) {
					t.Fatal("prepare repaired or replaced a file", i)
				}
			}
		})
	}
}
