//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func intrusionRuntimeFixture(t *testing.T) (*Service, map[string]string, *int) {
	t.Helper()
	s, answers, calls := intrusionInspectionFixture(t)
	answers["/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState"] = "MainPID=123\nActiveState=active\n"
	answers["/usr/bin/fail2ban-client get sshd journalmatch"] = "Current match filter:\n_SYSTEMD_UNIT=sshd.service + _COMM=sshd\n"
	answers["/usr/bin/fail2ban-client get sshd process-start"] = "10000\n"
	metadata, err := json.Marshal(intrusionDeclaredFilterMetadata("1.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	answers["/usr/bin/fail2ban-client get sshd filter-metadata"] = string(metadata)
	answers["/usr/bin/fail2ban-client get sshd action nftables chain"] = "<known/chain>\n"
	answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = intrusionObservedLazyStart
	policy := intrusionManagedPolicy{Format: 1, Action: "nftables", Name: "probe_sshd", Table: "f2b-table", Chain: "f2b-chain", IPv4Set: "addr-set-probe_sshd", IPv6Set: "addr6-set-probe_sshd", Ports: []int{22}, MaxMatches: 5}
	answers["/usr/bin/fail2ban-client get sshd maxmatches"] = "5\n"
	answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionActionRecipeFixture(t, policy)
	return s, answers, calls
}

func TestIntrusionMutationRuntimeRechecksKernelNotJustDaemonProperties(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"rule-handle":    func(v map[string]any) { intrusionNftOwnRule(v)["handle"] = float64(333) },
		"chain-handle":   func(v map[string]any) { intrusionNftChain(v)["handle"] = float64(334) },
		"set-handle":     func(v map[string]any) { intrusionNftOwnSet(v)["handle"] = float64(335) },
		"new-actual-ban": func(v map[string]any) { intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.2"} },
	} {
		t.Run(name, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			run := s.Config.Run
			changed := false
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				raw, err := run(ctx, program, args...)
				if !changed && program == "/usr/sbin/nft" {
					var v map[string]any
					if json.Unmarshal([]byte(raw), &v) != nil {
						t.Fatal("fixture malformed")
					}
					change(v)
					answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, v))
					changed = true
				}
				return raw, err
			}
			if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil || !changed {
				t.Fatal("kernel-only drift accepted", err)
			}
		})
	}
}

func TestIntrusionMutationRuntimeRechecksDeferredDirectory(t *testing.T) {
	s, answers, _ := intrusionRuntimeFixture(t)
	answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
	answers["/usr/sbin/nft -j list tables"] = `{"nftables":[]}`
	run := s.Config.Run
	changed := false
	s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
		raw, err := run(ctx, program, args...)
		if !changed && program == "/usr/sbin/nft" && strings.Join(args, " ") == "-j list tables" {
			answers["/usr/sbin/nft -j list tables"] = `{"nftables":[{"table":{"family":"inet","name":"f2b-table","handle":9}}]}`
			changed = true
		}
		return raw, err
	}
	if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil || !changed {
		t.Fatal("lazy-to-present race accepted", err)
	}
}

func TestIntrusionMutationRuntimeChecksCompleteRecipeAndItsGeneration(t *testing.T) {
	for _, kind := range []string{"custom-reload", "changed-epoch"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			key := "/usr/bin/fail2ban-client get sshd actionproperties nftables"
			var recipe intrusionActionRecipe
			json.Unmarshal([]byte(answers[key]), &recipe)
			if kind == "custom-reload" {
				recipe.Values["actionreload"] = "echo private-backend-sentinel"
				raw, _ := json.Marshal(recipe)
				answers[key] = string(raw)
			} else {
				run := s.Config.Run
				changed := false
				s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
					raw, err := run(ctx, program, args...)
					if !changed && program == "/usr/sbin/nft" {
						recipe.Values["banEpoch"] = "1"
						data, _ := json.Marshal(recipe)
						answers[key] = string(data)
						changed = true
					}
					return raw, err
				}
			}
			if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil || strings.Contains(err.Error(), "private-backend-sentinel") {
				t.Fatal("custom or changing recipe accepted or leaked", err)
			}
		})
	}
}

func TestIntrusionMutationRuntimeCapturesActualStablePolicyWithoutWriting(t *testing.T) {
	s, _, calls := intrusionRuntimeFixture(t)
	out, err := s.readIntrusionMutationRuntime(context.Background())
	if err != nil || out.KernelState != "rules_observed" || len(out.Kernel) == 0 || len(out.KernelDirectory) != 0 || out.Process != "123" || out.ProcessStart != "10000" || out.Policy.Action != "nftables" || out.Policy.Chain != "f2b-chain" || out.Policy.Name != "probe_sshd" || !reflect.DeepEqual(out.SSHPorts, []int{22}) || !reflect.DeepEqual(out.Settings, map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}) || len(out.Bans) != 0 || *calls != 46 {
		t.Fatal(out, err, *calls)
	}
}

func TestIntrusionMutationRuntimeKeepsDeferredTableAndSharedScopeDistinct(t *testing.T) {
	for _, state := range []string{"table_absent", "scope_absent"} {
		t.Run(state, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			if state == "table_absent" {
				answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
				answers["/usr/sbin/nft -j list tables"] = `{"nftables":[]}`
			} else {
				answers["/usr/sbin/nft -j list table inet f2b-table"] = string(intrusionNftEncode(t, intrusionLazySharedTable(t)))
			}
			out, err := s.readIntrusionMutationRuntime(context.Background())
			if err != nil || out.KernelState != state || len(out.Bans) != 0 {
				t.Fatal(out, err)
			}
			if state == "table_absent" && (len(out.Kernel) != 0 || len(out.KernelDirectory) == 0) {
				t.Fatal("known absence lost original full directory")
			}
			if state == "scope_absent" && (len(out.Kernel) == 0 || len(out.KernelDirectory) != 0) {
				t.Fatal("shared policy snapshot discarded")
			}
		})
	}
}

func TestIntrusionMutationRuntimeRefusesUnsupportedOrInconsistentBeforeState(t *testing.T) {
	for name, pair := range map[string][2]string{
		"file-backend":       {"/usr/bin/fail2ban-client get sshd journalmatch", "ERROR"},
		"unknown-journal":    {"/usr/bin/fail2ban-client get sshd journalmatch", "Current match filter:\n_COMM=anything\n"},
		"inactive":           {"/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState", "MainPID=123\nActiveState=inactive\n"},
		"zero-pid":           {"/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState", "MainPID=0\nActiveState=active\n"},
		"duplicate-process":  {"/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState", "MainPID=123\nMainPID=124\nActiveState=active\n"},
		"port-alias":         {"/usr/bin/fail2ban-client get sshd action nftables port", "ssh\n"},
		"new-protocol":       {"/usr/bin/fail2ban-client get sshd action nftables protocol", "tcp,udp\n"},
		"custom-command":     {"/usr/bin/fail2ban-client get sshd action nftables actionstart", intrusionObservedLazyStart + "echo private-backend-sentinel\n"},
		"noncanonical-limit": {"/usr/bin/fail2ban-client get sshd maxretry", "05\n"},
		"partial-minute":     {"/usr/bin/fail2ban-client get sshd findtime", "601\n"},
		"out-of-bounds":      {"/usr/bin/fail2ban-client get sshd maxretry", "21\n"},
		"extra-action":       {"/usr/bin/fail2ban-client get sshd actions", "The jail sshd has the following actions:\nnftables, mail\n"},
		"wrong-family":       {"/usr/bin/fail2ban-client get sshd action nftables table_family", "ip\n"},
		"unmatched-live-ban": {"/usr/bin/fail2ban-client get sshd banip", "127.0.0.2\n"},
	} {
		t.Run(name, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			answers[pair[0]] = pair[1]
			_, err := s.readIntrusionMutationRuntime(context.Background())
			if err == nil || strings.Contains(err.Error(), "private-backend-sentinel") || strings.Contains(err.Error(), "secret backend") {
				t.Fatal("unverified before state accepted or leaked", err)
			}
		})
	}
}

func TestIntrusionMutationRuntimeRejectsTornIndividuallyValidSamples(t *testing.T) {
	for name, change := range map[string]func(map[string]string){
		"ports": func(a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd action nftables port"] = "23\n"
			a["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = strings.ReplaceAll(intrusionObservedLazyStart, "'22'", "'23'")
		},
		"limits": func(a map[string]string) { a["/usr/bin/fail2ban-client get sshd maxretry"] = "6\n" },
		"backend-match": func(a map[string]string) {
			a["/usr/bin/fail2ban-client get sshd journalmatch"] = "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd\n"
		},
		"process": func(a map[string]string) {
			a["/usr/bin/systemctl show fail2ban.service --property=MainPID,ActiveState"] = "ActiveState=active\nMainPID=124\n"
		},
		"bans": func(a map[string]string) { a["/usr/bin/fail2ban-client get sshd banip"] = "127.0.0.2\n" },
	} {
		t.Run(name, func(t *testing.T) {
			s, answers, _ := intrusionRuntimeFixture(t)
			run := s.Config.Run
			changed := false
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				value, err := run(ctx, program, args...)
				if !changed && program == "/usr/sbin/nft" {
					change(answers)
					changed = true
				}
				return value, err
			}
			if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil || !changed {
				t.Fatal("torn sample became transaction authority", err)
			}
		})
	}
}

func TestIntrusionFail2banProcessAndJournalGrammarNeverGuessesAService(t *testing.T) {
	for _, raw := range []string{"ActiveState=active\nMainPID=0123\n", "ActiveState=active\nMainPID=123\nUnit=other\n", "ActiveState=active\nMainPID=123", "ActiveState=active\nMainPID=123\r\n"} {
		if _, err := intrusionFail2banProcess(raw); err == nil {
			t.Fatal("unknown process sample accepted", raw)
		}
	}
	if pid, err := intrusionFail2banProcess("ActiveState=active\nMainPID=123\n"); err != nil || pid != "123" {
		t.Fatal(pid, err)
	}
}

func TestIntrusionJournalMatchAcceptsOnlyCompleteDistributionGrammar(t *testing.T) {
	for _, match := range []string{
		"_SYSTEMD_UNIT=sshd.service + _COMM=sshd",
		"_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
		"_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session",
	} {
		t.Run(match, func(t *testing.T) {
			got, err := intrusionRuntimeJournalMatch("Current match filter:\n" + match + "\n")
			if err != nil || got != match {
				t.Fatal("complete distro match was changed or refused", got, err)
			}
		})
	}
	for name, raw := range map[string]string{
		"foreign-unit":      "Current match filter:\n_SYSTEMD_UNIT=other.service + _COMM=sshd + _COMM=sshd-session\n",
		"foreign-process":   "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=other\n",
		"incomplete-groups": "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd-session\n",
		"reordered":         "Current match filter:\n_COMM=sshd-session + _COMM=sshd + _SYSTEMD_UNIT=ssh.service\n",
		"duplicate":         "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd\n",
		"missing-banner":    "_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\n",
		"truncated":         "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session",
		"carriage-return":   "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\r\n",
		"trailing-output":   "Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\nOK\n",
		"unknown-spacing":   "Current match filter:\n_SYSTEMD_UNIT=ssh.service  + _COMM=sshd + _COMM=sshd-session\n",
		"prefixed-output":   "warning\nCurrent match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\n",
		"missing-unit":      "Current match filter:\n_COMM=sshd + _COMM=sshd-session\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := intrusionRuntimeJournalMatch(raw); err == nil || got != "" {
				t.Fatal("partial or foreign match became backend authority", got, err)
			}
		})
	}
}
