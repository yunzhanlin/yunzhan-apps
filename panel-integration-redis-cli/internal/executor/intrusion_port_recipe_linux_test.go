//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"math/bits"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestIntrusionPortRecipeModelsAllOriginalLiteralTransitionsWithoutExecuting(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		for _, state := range []string{"committed", "rolled_back"} {
			t.Run(fmt.Sprintf("%d-%s", mask, state), func(t *testing.T) {
				original := intrusionJournalFixture(t)
				var current intrusionActionRecipe
				if err := json.Unmarshal([]byte(intrusionRecipeJSON(original.ActionBefore)), &current); err != nil {
					t.Fatal(err)
				}
				after, err := intrusionPortRecipeTarget(original)
				if err != nil {
					t.Fatal(err)
				}
				for i, key := range []string{"actionstart", "actionflush", "port"} {
					if mask&(1<<i) != 0 {
						current.Values[key] = after[key]
					}
				}
				before := intrusionRecipeJSON(current)
				plan, err := intrusionPortRecipeChanges(original, current, state)
				wanted := bits.OnesCount(uint(mask))
				if state == "committed" {
					wanted = 3 - wanted
				}
				if err != nil || len(plan.Changes) != wanted || plan.Process != original.ProcessBefore || plan.Action != original.BeforePolicy.Action {
					t.Fatal(plan, err, wanted)
				}
				for _, change := range plan.Changes {
					if !slices.Contains([]string{"actionstart", "actionflush", "port"}, change.Field) || change.From == change.To {
						t.Fatal("arbitrary or empty action intention", change.Field)
					}
				}
				if intrusionRecipeJSON(current) != before {
					t.Fatal("model modified actual observation")
				}
				// The ordinary validator must NOT become a public loose-mode flag.
				if mask != 0 && mask != 7 {
					if _, err := intrusionActionRecipeValidate(before, original.BeforePolicy); err == nil {
						t.Fatal("ordinary validator silently accepted a transaction-only mixed recipe")
					}
				}
			})
		}
	}
}

func TestIntrusionPortRecipeRejectsThirdStatesMissingEmptyVerbsAndInitOptions(t *testing.T) {
	for _, kind := range []string{"third-port", "modified-start", "modified-flush", "missing-empty-verb", "extra-type", "unknown-property", "changed-generation", "changed-protocol"} {
		t.Run(kind, func(t *testing.T) {
			original := intrusionJournalFixture(t)
			var current intrusionActionRecipe
			json.Unmarshal([]byte(intrusionRecipeJSON(original.ActionBefore)), &current)
			switch kind {
			case "third-port":
				current.Values["port"] = "2222"
			case "modified-start":
				current.Values["actionstart"] += "; external-command"
			case "modified-flush":
				current.Values["actionflush"] += "; external-command"
			case "missing-empty-verb":
				delete(current.Values, "actionreload")
			case "extra-type":
				current.Properties = append(current.Properties, "type")
				slices.Sort(current.Properties)
				current.Values["type"] = "multiport"
			case "unknown-property":
				current.Properties = append(current.Properties, "actionprolong")
				slices.Sort(current.Properties)
			case "changed-generation":
				current.Values["banEpoch"] = "1"
			case "changed-protocol":
				current.Values["protocol"] = "udp"
			}
			plan, err := intrusionPortRecipeChanges(original, current, "committed")
			if err == nil || !reflect.DeepEqual(plan, intrusionPortRecipePlan{}) {
				t.Fatal("foreign action produced partial writer intent", err)
			}
		})
	}
}

func TestIntrusionPortRecipeDecoderRejectsDuplicateUnknownTrailingAndTruncatedData(t *testing.T) {
	p := intrusionJournalFixture(t)
	raw := intrusionRecipeJSON(p.ActionBefore)
	for _, bad := range []string{strings.Replace(raw, `"format":1`, `"format":1,"FORMAT":1`, 1), strings.Replace(raw, `"format":1`, `"format":1,"force":true`, 1), raw + `{}`, raw[:len(raw)/2]} {
		if _, err := intrusionPortRecipeDecode(bad, p); err == nil {
			t.Fatal("nonclosed action recipe accepted")
		}
	}
}

func TestIntrusionPendingRuntimeMayObserveOnlyOriginalIndependentLiteralPortFields(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			s, answers, _, lock, p, raw := intrusionPendingObservationFixture(t)
			var recipe intrusionActionRecipe
			json.Unmarshal([]byte(intrusionRecipeJSON(p.ActionBefore)), &recipe)
			after, err := intrusionPortRecipeTarget(p)
			if err != nil {
				t.Fatal(err)
			}
			for i, key := range []string{"actionstart", "actionflush", "port"} {
				if mask&(1<<i) != 0 {
					recipe.Values[key] = after[key]
				}
			}
			answers["/usr/bin/fail2ban-client get sshd action nftables port"] = recipe.Values["port"] + "\n"
			answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = recipe.Values["actionstart"] + "\n"
			answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionRecipeJSON(recipe)
			out, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw)
			if err != nil || !reflect.DeepEqual(out.Recipe, recipe) {
				t.Fatal("bound literal transition refused or repaired", mask, err)
			}
			if mask != 0 && mask != 7 {
				if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil {
					t.Fatal("ordinary runtime accepted mixed literal recipe")
				}
			}
		})
	}
}

func TestIntrusionPendingRuntimeRejectsThirdLiteralTemplatesAndInconsistentPortSamples(t *testing.T) {
	for _, kind := range []string{"start", "flush", "port-sample"} {
		t.Run(kind, func(t *testing.T) {
			s, answers, _, lock, p, raw := intrusionPendingObservationFixture(t)
			var recipe intrusionActionRecipe
			json.Unmarshal([]byte(intrusionRecipeJSON(p.ActionBefore)), &recipe)
			switch kind {
			case "start":
				recipe.Values["actionstart"] += "; external-command"
				answers["/usr/bin/fail2ban-client get sshd action nftables actionstart"] = recipe.Values["actionstart"] + "\n"
			case "flush":
				recipe.Values["actionflush"] += "; external-command"
			case "port-sample":
				recipe.Values["port"] = "2882"
			}
			answers["/usr/bin/fail2ban-client get sshd actionproperties nftables"] = intrusionRecipeJSON(recipe)
			if _, err := s.readIntrusionTransactionRuntime(context.Background(), lock, p, raw); err == nil {
				t.Fatal("foreign literal or torn property observation accepted")
			}
		})
	}
}

func TestIntrusionOriginalEntryPointsStillValidateBeforeSharingPureDerivations(t *testing.T) {
	for _, kind := range []string{"format", "version", "target-ports", "derived-file", "tree-digest", "original-command"} {
		t.Run(kind, func(t *testing.T) {
			p, current := intrusionScalarFixture(t)
			bans, err := intrusionBannedAddresses(strings.Join(p.BansBefore, " "))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "format":
				p.Format = 2
			case "version":
				p.TargetVersion = "9.9.9"
			case "target-ports":
				p.TargetPorts = []int{0}
			case "derived-file":
				p.Files[0].After.Data = append(p.Files[0].After.Data, ' ')
			case "tree-digest":
				entry := p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
				entry.SHA256 = strings.Repeat("a", 64)
				p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"] = entry
			case "original-command":
				p.ActionBefore.Values["actionban"] += "; external-command"
			}
			if _, err := intrusionPortRecipeDecode(intrusionRecipeJSON(current.Recipe), p); err == nil {
				t.Fatal("recipe entry skipped original validation")
			}
			if _, err := intrusionPortRecipeChanges(p, current.Recipe, "committed"); err == nil {
				t.Fatal("recipe intention entry skipped original validation")
			}
			if _, err := intrusionProjectCurrentKernelPorts(p, p.KernelBefore, bans); err == nil {
				t.Fatal("projection entry skipped original validation")
			}
			if _, err := intrusionJournalKernelAccept(p, p.KernelBefore, nil, bans); err == nil {
				t.Fatal("kernel entry skipped original validation")
			}
			if _, err := intrusionJournalScalarPlan(p, current, "committed"); err == nil {
				t.Fatal("scalar entry skipped original validation")
			}
		})
	}
}
