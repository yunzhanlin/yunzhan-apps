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

	"local/panel/internal/core"
)

func intrusionTerminalDumpFixture(t *testing.T, p intrusionJournalPlan, after bool) []byte {
	t.Helper()
	var dump intrusionEffectiveDump
	if err := json.Unmarshal(intrusionEffectiveARMFixture, &dump); err != nil {
		t.Fatal(err)
	}
	policy := p.BeforePolicy
	settings, err := intrusionJournalBeforeSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if after {
		policy.Ports = slices.Clone(p.TargetPorts)
		settings = p.TargetSettings
	}
	values, err := intrusionStockActionValues(policy, p.ActionBefore.Values["nftables"], p.ActionBefore.Values["chain"])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range dump.Commands {
		if len(c) < 4 || c[1] != "sshd" {
			continue
		}
		switch c[2] {
		case "maxretry":
			c[3] = float64(settings["max_retry"])
		case "findtime":
			c[3] = float64(settings["find_time_minutes"] * 60)
		case "bantime":
			c[3] = float64(settings["ban_time_minutes"] * 60)
		case "action":
			for _, v := range c[4].([]any) {
				pair := v.([]any)
				pair[1] = values[pair[0].(string)]
			}
		}
	}
	raw, err := json.Marshal(dump)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func intrusionTerminalFixture(t *testing.T, state string) (*Service, map[string]string, *os.File, intrusionJournalPlan, []byte) {
	return intrusionTerminalFixtureWithSetup(t, state, nil)
}

func intrusionTerminalFixtureWithSetup(t *testing.T, state string, change func(*Service, *intrusionJournalPlan)) (*Service, map[string]string, *os.File, intrusionJournalPlan, []byte) {
	t.Helper()
	s, answers, _, lock, p, raw := intrusionPendingObservationFixtureWithSetup(t, func(s *Service, answers map[string]string, p *intrusionJournalPlan) {
		if change != nil {
			change(s, p)
		}
		live := intrusionRuntimeState{Policy: p.BeforePolicy, Recipe: p.ActionBefore, JournalMatch: p.JournalMatchBefore}
		before, err := intrusionJournalBeforeSettings(*p)
		if err != nil {
			t.Fatal(err)
		}
		dump, err := intrusionEffectiveConfigurationDecode(intrusionTerminalDumpFixture(t, *p, false), live, before)
		if err != nil {
			t.Fatal(err)
		}
		p.EffectiveBefore = dump.Identity
	})
	oldRun := s.Config.Run
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/python3" {
			return oldRun(ctx, name, args...)
		}
		if !slices.Equal(args, []string{"-I", "-B", "-c", intrusionConfigurationDumpScript}) {
			t.Fatal("terminal reached a mutator or unknown script")
		}
		jail, err := s.intrusionConfigObservation()
		if err != nil {
			return "", err
		}
		return string(intrusionTerminalDumpFixture(t, p, bytes.Equal(jail.data, p.Files[0].After.Data))), nil
	}
	if state == "committed" {
		for i := 0; i < 3; i++ {
			if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, i, state); err != nil {
				t.Fatal(err)
			}
		}
		answers["/usr/bin/fail2ban-client get sshd action nftables port"] = "2882\n"
		answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = strings.ReplaceAll(intrusionObservedLazyStart, "'22'", "'2882'")
		policy := p.BeforePolicy
		policy.Ports = []int{2882}
		answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionActionRecipeFixture(t, policy)
		answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, []int{2882})
	}
	return s, answers, lock, p, raw
}

func TestIntrusionJournalTerminalRequiresActualCompleteCommitOrRollback(t *testing.T) {
	for _, state := range []string{"committed", "rolled_back"} {
		t.Run(state, func(t *testing.T) {
			s, _, lock, p, raw := intrusionTerminalFixture(t, state)
			if err := s.intrusionJournalVerifyState(context.Background(), lock, p, raw, state); err != nil {
				t.Fatal(err)
			}
			if inventory, err := s.intrusionJournalInventoryRead(); err != nil || len(inventory.Records) != 0 {
				t.Fatal("verification created terminal", err)
			}
		})
	}
}

func TestIntrusionJournalTerminalPublishIsImmutableAndClosesOnlyOriginalReceipt(t *testing.T) {
	s, _, lock, p, raw := intrusionTerminalFixture(t, "committed")
	ctx := context.Background()
	if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory, p.ID+".json")
	before, _ := os.Lstat(file)
	data, _ := os.ReadFile(file)
	if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "committed", ""); err != nil {
		t.Fatal("idempotent publication changed original", err)
	}
	after, _ := os.Lstat(file)
	again, _ := os.ReadFile(file)
	if !os.SameFile(before, after) || !bytes.Equal(data, again) || before.ModTime() != after.ModTime() {
		t.Fatal("immutable terminal rewritten")
	}
	if err := s.intrusionJournalCloseTerminal(ctx, lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending not closed", err)
	}
	if _, err := s.intrusionJournalPrepare(lock, p); err == nil {
		t.Fatal("closed original identity replayed")
	}
	again, _ = os.ReadFile(file)
	if !bytes.Equal(data, again) {
		t.Fatal("original receipt changed after close/replay refusal")
	}
}

func TestIntrusionJournalTerminalRollbackRequiresSeparateRecoveryIdentity(t *testing.T) {
	s, _, lock, p, raw := intrusionTerminalFixture(t, "rolled_back")
	recovery := core.ID()
	ctx := context.Background()
	if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "rolled_back", recovery); err != nil {
		t.Fatal(err)
	}
	if err := s.intrusionJournalCloseTerminal(ctx, lock, p, raw, "rolled_back", core.ID()); err == nil {
		t.Fatal("another recovery identity closed original")
	}
	if err := s.intrusionJournalCloseTerminal(ctx, lock, p, raw, "rolled_back", recovery); err != nil {
		t.Fatal(err)
	}
}

func TestIntrusionJournalTerminalNeverPublishesOnFileDaemonKernelOrEffectiveDrift(t *testing.T) {
	for _, kind := range []string{"manifest", "policy", "limits", "action-port", "kernel-port", "effective-filter", "effective-global", "changing-pending"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, lock, p, raw := intrusionTerminalFixture(t, "committed")
			switch kind {
			case "manifest", "policy":
				slot := 1
				if kind == "policy" {
					slot = 2
				}
				if err := os.WriteFile(s.intrusionJournalPaths()[slot], []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "limits":
				answers["/usr/bin/fail2ban-client get sshd maxretry"] = "7\n"
			case "action-port":
				answers["/usr/bin/fail2ban-client get sshd action nftables port"] = "22\n"
			case "kernel-port":
				answers["/usr/sbin/nft -j list table inet f2b-table"] = intrusionInspectionKernelFixture(t, []int{22})
			default:
				run := s.Config.Run
				s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
					out, err := run(ctx, name, args...)
					if name != "/usr/bin/python3" {
						return out, err
					}
					if kind == "changing-pending" {
						if err := os.WriteFile(filepath.Join(s.Config.SecurityDir, intrusionPendingName), []byte("{}\n"), 0600); err != nil {
							t.Fatal(err)
						}
						return out, err
					}
					var dump intrusionEffectiveDump
					json.Unmarshal([]byte(out), &dump)
					if kind == "effective-global" {
						dump.Commands[0][2] = "foreign-global"
					} else {
						for _, c := range dump.Commands {
							if len(c) == 4 && c[1] == "sshd" && c[2] == "prefregex" {
								c[3] = "foreign-filter"
							}
						}
					}
					v, _ := json.Marshal(dump)
					return string(v), nil
				}
			}
			if err := s.intrusionJournalWriteTerminal(context.Background(), lock, p, raw, "committed", ""); err == nil {
				t.Fatal("unverified success published")
			}
			if inventory, err := s.intrusionJournalInventoryRead(); err != nil || len(inventory.Records) != 0 {
				t.Fatal("failed verification published terminal", err)
			}
			if _, err := os.Lstat(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
				t.Fatal("failed verification cleared original pending", err)
			}
		})
	}
}

func TestIntrusionJournalTerminalCannotClearMissingConflictingOrUnverifiedReceipt(t *testing.T) {
	for _, kind := range []string{"missing", "different-state", "different-recovery", "different-plan", "runtime-drift"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, lock, p, raw := intrusionTerminalFixture(t, "committed")
			file := filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory, p.ID+".json")
			if kind != "missing" {
				if err := s.intrusionJournalWriteTerminal(context.Background(), lock, p, raw, "committed", ""); err != nil {
					t.Fatal(err)
				}
				if kind == "runtime-drift" {
					answers["/usr/bin/fail2ban-client get sshd maxretry"] = "7\n"
				} else {
					data, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					var terminal intrusionJournalTerminal
					json.Unmarshal(data, &terminal)
					switch kind {
					case "different-state":
						terminal.State = "rolled_back"
					case "different-recovery":
						terminal.State, terminal.RecoveryJobID = "rolled_back", core.ID()
					case "different-plan":
						terminal.Plan.ActionBefore.Values["banEpoch"] = "1"
						planRaw, _ := intrusionJournalEncode(terminal.Plan)
						terminal.PlanSHA256 = hardeningJournalDigest(planRaw)
					}
					data, _ = intrusionJournalEncode(terminal)
					if err := os.WriteFile(file, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _ := os.ReadFile(file)
			if err := s.intrusionJournalCloseTerminal(context.Background(), lock, p, raw, "committed", ""); err == nil {
				t.Fatal("unverified terminal cleared pending")
			}
			after, _ := os.ReadFile(file)
			_, again, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(raw, again) || !bytes.Equal(before, after) {
				t.Fatal("refused close rewrote original authority", err)
			}
		})
	}
}

func TestIntrusionJournalTerminalRetainsPartialTemporaryWithoutPromotingIt(t *testing.T) {
	s, _, lock, p, raw := intrusionTerminalFixture(t, "committed")
	file := filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory, ".intrusion-terminal-"+core.ID()+".tmp")
	if err := os.WriteFile(file, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(file)
	if err := s.intrusionJournalWriteTerminal(context.Background(), lock, p, raw, "committed", ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Lstat(file)
	data, _ := os.ReadFile(file)
	if !os.SameFile(before, after) || string(data) != "{" || before.ModTime() != after.ModTime() {
		t.Fatal("incomplete old record was promoted or deleted")
	}
}

func TestIntrusionJournalTerminalArchiveRequiresOriginalNamedDirectory(t *testing.T) {
	s, _, _, _, _ := intrusionTerminalFixture(t, "committed")
	root, err := s.intrusionJournalArchiveRoot(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	path := filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory)
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.intrusionJournalArchiveCurrent(root); err == nil {
		t.Fatal("replaced archive accepted")
	}
}

func TestIntrusionJournalTerminalCancelledRequestCannotPublishOrClearPending(t *testing.T) {
	s, _, lock, p, raw := intrusionTerminalFixture(t, "committed")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "committed", ""); err == nil {
		t.Fatal("cancelled request published success")
	}
	if err := s.intrusionJournalCloseTerminal(ctx, lock, p, raw, "committed", ""); err == nil {
		t.Fatal("cancelled request cleared pending")
	}
	_, again, err := s.intrusionJournalPending()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("cancelled request changed pending", err)
	}
}
