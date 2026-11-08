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
	"slices"
	"testing"

	"local/panel/internal/core"
)

func intrusionRemovalPlanSetup(t *testing.T, p *intrusionJournalPlan, ports []int) {
	t.Helper()
	p.Action = "uninstall"
	p.TargetSettings = map[string]int{"max_retry": 7, "find_time_minutes": 12, "ban_time_minutes": 120}
	p.TargetPorts = slices.Clone(ports)
	before, err := intrusionJournalBeforeSettings(*p)
	if err != nil {
		t.Fatal(err)
	}
	current := intrusionRuntimeState{Policy: p.BeforePolicy, Recipe: p.ActionBefore, JournalMatch: p.JournalMatchBefore}
	full, err := intrusionEffectiveConfigurationDecode(intrusionTerminalDumpFixture(t, *p, false), current, before)
	if err != nil {
		t.Fatal(err)
	}
	p.EffectiveBefore = full.Identity
	p.Removal = &intrusionRemovalEvidence{Dump: intrusionTerminalDumpFixture(t, *p, true), SSHPorts: []int{2882}}
}

func TestIntrusionRemovalOriginalDerivesOnlyThreeAbsentFilesAndIndependentTargets(t *testing.T) {
	for _, ports := range [][]int{{22}, {22, 28080}} {
		t.Run(map[bool]string{true: "same-action-port", false: "different-underlying-port"}[len(ports) == 1], func(t *testing.T) {
			p := intrusionJournalFixture(t)
			intrusionRemovalPlanSetup(t, &p, ports)
			p, err := intrusionJournalDerive(p)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := intrusionJournalEncode(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := intrusionJournalDecode(raw)
			if err != nil || !reflect.DeepEqual(got, p) {
				t.Fatal("original removal evidence not canonical", err)
			}
			for _, file := range got.Files {
				if !reflect.DeepEqual(file.After, hardeningJournalFile{}) {
					t.Fatal("removal invented target file", file.Name)
				}
			}
			ssh := intrusionJournalObservedSSHPorts(got)
			if !slices.Equal(ssh, []int{2882}) || !slices.Equal(got.TargetPorts, ports) {
				t.Fatal("underlying action confused with SSH listener")
			}
			ssh[0] = 1234
			if got.Removal.SSHPorts[0] != 2882 {
				t.Fatal("returned SSH ports alias original")
			}
			current := intrusionRuntimeState{Policy: p.BeforePolicy, Recipe: p.ActionBefore, JournalMatch: p.JournalMatchBefore}
			candidate, err := intrusionRemovalCandidateDecode(got.Removal.Dump, current, p.EffectiveBefore)
			if err != nil || !maps.Equal(candidate.Settings, p.TargetSettings) {
				t.Fatal(err)
			}
			candidate.dump[0] = ' '
			again, _ := intrusionJournalEncode(got)
			if !bytes.Equal(raw, again) {
				t.Fatal("private candidate aliased immutable original dump")
			}
		})
	}
}

func TestIntrusionRemovalOriginalRejectsGuessedOrTamperedAuthority(t *testing.T) {
	for name, change := range map[string]func(*intrusionJournalPlan){
		"missing-evidence":   func(p *intrusionJournalPlan) { p.Removal = nil },
		"missing-dump":       func(p *intrusionJournalPlan) { p.Removal.Dump = nil },
		"truncated-dump":     func(p *intrusionJournalPlan) { p.Removal.Dump = p.Removal.Dump[:len(p.Removal.Dump)/2] },
		"extra-document":     func(p *intrusionJournalPlan) { p.Removal.Dump = append(p.Removal.Dump, []byte("{}")...) },
		"oversize-dump":      func(p *intrusionJournalPlan) { p.Removal.Dump = bytes.Repeat([]byte(" "), 32769) },
		"missing-SSH":        func(p *intrusionJournalPlan) { p.Removal.SSHPorts = nil },
		"unsorted-SSH":       func(p *intrusionJournalPlan) { p.Removal.SSHPorts = []int{2882, 22} },
		"invalid-SSH":        func(p *intrusionJournalPlan) { p.Removal.SSHPorts = []int{0} },
		"guessed-limit":      func(p *intrusionJournalPlan) { p.TargetSettings["max_retry"] = 8 },
		"guessed-port":       func(p *intrusionJournalPlan) { p.TargetPorts = []int{23} },
		"invented-file":      func(p *intrusionJournalPlan) { p.Files[0].After = p.Files[0].Before },
		"dirty-absence":      func(p *intrusionJournalPlan) { p.Files[1].After.Mode = 0600 },
		"different-identity": func(p *intrusionJournalPlan) { p.EffectiveBefore = core.Hash("different") },
		"missing-owned-jail": func(p *intrusionJournalPlan) { p.Files[0].Before = hardeningJournalFile{} },
		"external-owned-jail": func(p *intrusionJournalPlan) {
			p.Files[0].Before.Data = append(p.Files[0].Before.Data, []byte("# external\n")...)
		},
		"install-authority":      func(p *intrusionJournalPlan) { p.InstallBeforeSettings = maps.Clone(p.TargetSettings) },
		"update-with-removal":    func(p *intrusionJournalPlan) { p.Action = "update" },
		"configure-with-removal": func(p *intrusionJournalPlan) { p.Action = "configure" },
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			intrusionRemovalPlanSetup(t, &p, []int{22})
			var err error
			p, err = intrusionJournalDerive(p)
			if err != nil {
				t.Fatal(err)
			}
			change(&p)
			before, _ := intrusionJournalEncode(p)
			if intrusionJournalValidate(p) == nil {
				t.Fatal("unqualified removal authority accepted")
			}
			after, _ := intrusionJournalEncode(p)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected authority repaired")
			}
		})
	}
}

func TestIntrusionRemovalAdvanceCommitsAbsenceWithoutStoppingBaseJail(t *testing.T) {
	for _, ports := range [][]int{{22}, {22, 28080}} {
		t.Run(map[bool]string{true: "same-ports", false: "changed-ports"}[len(ports) == 1], func(t *testing.T) {
			s, lock, p, raw, d, answers := intrusionAdvanceFixtureWithSetup(t, func(_ *Service, p *intrusionJournalPlan) { intrusionRemovalPlanSetup(t, p, ports) })
			if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err != nil {
				t.Fatal(err)
			}
			for _, name := range s.intrusionJournalPaths() {
				if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("owned file remains", err)
				}
			}
			wantedScalars, wantedTemplates, wantedNft := 3, 0, 0
			if len(ports) > 1 {
				wantedScalars, wantedTemplates, wantedNft = 4, 2, 1
			}
			if len(d.Scalars) != wantedScalars || len(d.Templates) != wantedTemplates || d.Checks != wantedNft || d.Applies != wantedNft || answers["/usr/bin/fail2ban-client get sshd maxmatches"] != "5\n" {
				t.Fatal("wrong steps, implicit reset or restart", d)
			}
			if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pending not closed", err)
			}
			inventory, err := s.intrusionJournalInventoryRead()
			if err != nil || inventory.Records[p.ID].State != "committed" || inventory.Records[p.ID].Plan.Action != "uninstall" {
				t.Fatal("missing immutable removal terminal", err)
			}
		})
	}
}

func TestIntrusionRemovalUnknownOutcomeOnlyExplicitlyRestoresExactOriginalFiles(t *testing.T) {
	intrusionRemovalUnknownOutcomeScenario(t, "scalar")
}

func TestIntrusionRemovalUnknownActionStartRestoresExactOriginalFiles(t *testing.T) {
	intrusionRemovalUnknownOutcomeScenario(t, "actionstart")
}

func TestIntrusionRemovalUnknownActionFlushRestoresExactOriginalFiles(t *testing.T) {
	intrusionRemovalUnknownOutcomeScenario(t, "actionflush")
}

func TestIntrusionRemovalUnknownKernelRestoresExactOriginalFiles(t *testing.T) {
	intrusionRemovalUnknownOutcomeScenario(t, "kernel")
}

// Each original independent failure scenario has a complete fresh fixture and
// recovery. Separate top-level tests preserve ALL assertions while allowing
// inventory scheduling under the unchanged per-process deadline.
func intrusionRemovalUnknownOutcomeScenario(t *testing.T, point string) {
	t.Helper()
	t.Run(point, func(t *testing.T) {
		s, lock, p, raw, d, _ := intrusionAdvanceFixtureWithSetup(t, func(_ *Service, p *intrusionJournalPlan) { intrusionRemovalPlanSetup(t, p, []int{22, 28080}) })
		switch point {
		case "scalar":
			d.LostScalar = true
		case "kernel":
			d.LostKernel = true
		default:
			d.LostTemplateField = point
		}
		if err := s.intrusionJournalAdvance(context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID), lock, p, raw, "committed", ""); err == nil {
			t.Fatal("unknown removal reported success")
		}
		_, pending, err := s.intrusionJournalPending()
		if err != nil || !bytes.Equal(pending, raw) {
			t.Fatal("original lost", err)
		}
		inventory, err := s.intrusionJournalInventoryRead()
		if err != nil || len(inventory.Records) != 0 {
			t.Fatal("unknown outcome published terminal", err)
		}
		d.LostScalar, d.LostKernel, d.LostTemplateField = false, false, ""
		lock.Close()
		job := core.ID()
		if err := s.recoverIntrusionOperation(context.WithValue(context.Background(), intrusionJobContextKey{}, job), map[string]any{"transaction_id": p.ID, "plan_sha256": hardeningJournalDigest(raw)}, func(string) {}); err != nil {
			t.Fatal(err)
		}
		files, err := s.intrusionJournalCurrentFiles()
		if err != nil {
			t.Fatal(err)
		}
		for i, file := range files {
			if !hardeningBackupSame(file, p.Files[i].Before.backup(s.intrusionJournalPaths()[i])) {
				t.Fatal("recovery did not restore exact original", i)
			}
		}
		inventory, err = s.intrusionJournalInventoryRead()
		if err != nil || inventory.Records[p.ID].State != "rolled_back" || inventory.Records[p.ID].RecoveryJobID != job {
			t.Fatal("missing original recovery terminal", err)
		}
	})
}

func TestIntrusionRemovalPrepareBindsPrivateCandidateAndNeverRequestDefaults(t *testing.T) {
	for _, kind := range []string{"ready", "user-settings", "missing-job", "candidate-error", "candidate-incomplete", "changed-source"} {
		t.Run(kind, func(t *testing.T) {
			s, _, lock, original, _ := intrusionTerminalFixture(t, "rolled_back")
			if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
				t.Fatal(err)
			} // ONLY fake fixture latch.
			target := intrusionJournalClone(t, original)
			intrusionRemovalPlanSetup(t, &target, []int{22})
			calls := 0
			run := s.Config.Run
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				if program != "/usr/bin/python3" || len(args) != 6 || !slices.Equal(args[:5], []string{"-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate"}) {
					return run(ctx, program, args...)
				}
				calls++
				if filepath.Dir(args[5]) != filepath.Join(s.Config.SecurityDir, intrusionRemovalCacheName) {
					t.Fatal("non-private candidate")
				}
				if _, err := os.Lstat(filepath.Join(args[5], "jail.d/panel-intrusion.local")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("owned Jail not omitted", err)
				}
				if kind == "candidate-error" {
					return "", errors.New("private backend sentinel")
				}
				if kind == "candidate-incomplete" {
					return "{}", nil
				}
				if kind == "changed-source" {
					if err := os.WriteFile(s.systemPath("/etc/fail2ban/jail.conf"), []byte("external change\n"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				return string(target.Removal.Dump), nil
			}
			job := core.ID()
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, job)
			var requested map[string]any
			if kind == "missing-job" {
				ctx = context.Background()
			}
			if kind == "user-settings" {
				requested = map[string]any{"max_retry": 9}
			}
			before, err := s.intrusionJournalCurrentFiles()
			if err != nil {
				t.Fatal(err)
			}
			p, raw, err := s.intrusionPrepareOperation(ctx, lock, "uninstall", requested)
			if kind == "ready" {
				if err != nil || p.ID != job || p.Action != "uninstall" || len(raw) == 0 || calls != 1 || !maps.Equal(p.TargetSettings, target.TargetSettings) || !slices.Equal(p.TargetPorts, []int{22}) || !slices.Equal(p.Removal.SSHPorts, []int{2882}) {
					t.Fatal("private derived preparation failed", err)
				}
			} else {
				if err == nil {
					t.Fatal("unqualified prepare accepted")
				}
				if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused removal created pending", err)
				}
			}
			wantedCalls := 1
			if kind == "user-settings" || kind == "missing-job" {
				wantedCalls = 0
			}
			if calls != wantedCalls {
				t.Fatal("candidate retried or improperly skipped", calls)
			}
			after, err := s.intrusionJournalCurrentFiles()
			if err != nil {
				t.Fatal(err)
			}
			for i := range before {
				if !hardeningBackupSame(before[i], after[i]) {
					t.Fatal("prepare removed or repaired original files", i)
				}
			}
		})
	}
}
