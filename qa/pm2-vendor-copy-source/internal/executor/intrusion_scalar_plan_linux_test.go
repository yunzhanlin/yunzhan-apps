//go:build linux

package executor

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

func intrusionScalarFixture(t *testing.T) (intrusionJournalPlan, intrusionRuntimeState) {
	t.Helper()
	p := intrusionJournalFixture(t)
	for i := range p.Files {
		p.Files[i].Before = p.Files[i].After
	}
	p.BeforePolicy.Ports = []int{2882}
	p.ConfigurationBefore = intrusionJournalTreeFixture(p.Files[0].Before)
	json.Unmarshal([]byte(intrusionActionRecipeFixture(t, p.BeforePolicy)), &p.ActionBefore)
	var kernel map[string]any
	if err := json.Unmarshal(p.KernelBefore, &kernel); err != nil {
		t.Fatal(err)
	}
	intrusionNftOwnRule(kernel)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2882)
	p.KernelBefore = intrusionNftEncode(t, kernel)
	p.Action = "configure"
	p.TargetSettings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
	p.TargetPorts = []int{2882, 2883}
	var err error
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	current := intrusionRuntimeState{Policy: p.BeforePolicy, Settings: map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}, Recipe: p.ActionBefore, Process: p.ProcessBefore, ProcessStart: p.ProcessStartBefore, JournalMatch: p.JournalMatchBefore, Bans: []netip.Addr{netip.MustParseAddr("127.0.0.3")}}
	current.Recipe = intrusionActionRecipe{}
	if err := json.Unmarshal([]byte(intrusionRecipeJSON(p.ActionBefore)), &current.Recipe); err != nil {
		t.Fatal(err)
	}
	return p, current
}

func TestIntrusionScalarPlanSupportsOnlyOriginalMixedStatesWithoutTouchingFiltersOrBans(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		for _, state := range []string{"committed", "rolled_back"} {
			t.Run(fmt.Sprintf("%02d-%s", mask, state), func(t *testing.T) {
				original, current := intrusionScalarFixture(t)
				for i, key := range []string{"max_retry", "find_time_minutes", "ban_time_minutes"} {
					if mask&(1<<i) != 0 {
						current.Settings[key] = original.TargetSettings[key]
					}
				}
				if mask&8 != 0 {
					current.Policy.Ports = slices.Clone(original.TargetPorts)
					json.Unmarshal([]byte(intrusionActionRecipeFixture(t, current.Policy)), &current.Recipe)
				}
				before, _ := json.Marshal(current)
				plan, err := intrusionJournalScalarPlan(original, current, state)
				wanted := bits.OnesCount(uint(mask))
				if state == "committed" {
					wanted = 4 - wanted
				}
				if err != nil || plan.Process != "123" || plan.Action != "nftables" || len(plan.Changes) != wanted {
					t.Fatal(plan, err, wanted)
				}
				for _, change := range plan.Changes {
					if !slices.Contains([]string{"maxretry", "findtime", "bantime", "port"}, change.Key) || change.From == change.To || change.From == "" || change.To == "" {
						t.Fatal("arbitrary actuator intent", change)
					}
				}
				after, _ := json.Marshal(current)
				if string(before) != string(after) {
					t.Fatal("plan rewrote current history")
				}
			})
		}
	}
}

func TestIntrusionScalarPlanRefusesForeignProcessActionCapacityOrValues(t *testing.T) {
	for name, change := range map[string]func(*intrusionRuntimeState){
		"process":               func(v *intrusionRuntimeState) { v.Process = "124" },
		"backend":               func(v *intrusionRuntimeState) { v.JournalMatch = "_SYSTEMD_UNIT=ssh.service + _COMM=sshd" },
		"third-limit":           func(v *intrusionRuntimeState) { v.Settings["max_retry"] = 7 },
		"unknown-limit":         func(v *intrusionRuntimeState) { v.Settings["unban"] = 1 },
		"capacity":              func(v *intrusionRuntimeState) { v.Policy.MaxMatches = 6 },
		"third-port":            func(v *intrusionRuntimeState) { v.Policy.Ports = []int{2222} },
		"table":                 func(v *intrusionRuntimeState) { v.Policy.Table = "other_table" },
		"generation":            func(v *intrusionRuntimeState) { v.Recipe.Values["banEpoch"] = "1" },
		"custom-reload":         func(v *intrusionRuntimeState) { v.Recipe.Values["actionreload"] = "stop all" },
		"actual-port-disagrees": func(v *intrusionRuntimeState) { v.Recipe.Values["port"] = "2882,2883" },
	} {
		t.Run(name, func(t *testing.T) {
			original, current := intrusionScalarFixture(t)
			change(&current)
			out, err := intrusionJournalScalarPlan(original, current, "rolled_back")
			if err == nil || !reflect.DeepEqual(out, intrusionScalarPlan{}) {
				t.Fatal("foreign observation produced partial mutation authority", out, err)
			}
		})
	}
	for _, state := range []string{"", "rollback --restart", "unban", "updated"} {
		original, current := intrusionScalarFixture(t)
		if _, err := intrusionJournalScalarPlan(original, current, state); err == nil {
			t.Fatal("unknown target state accepted")
		}
	}
}

func TestIntrusionJournalPreservesIndependentMatchCapacityInDerivedJail(t *testing.T) {
	original, _ := intrusionScalarFixture(t)
	if original.BeforePolicy.MaxMatches != 5 || original.TargetSettings["max_retry"] != 6 {
		t.Fatal("fixture lost independent values")
	}
	if string(original.Files[0].After.Data) == "" {
		t.Fatal("derived jail missing")
	}
	var policy intrusionManagedPolicy
	if err := json.Unmarshal(original.Files[2].After.Data, &policy); err != nil || policy.MaxMatches != 5 {
		t.Fatal("policy silently changed capacity", err)
	}
	expected, err := renderIntrusionManagedScope(map[string]any{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}, policy)
	if err != nil || expected != string(original.Files[0].After.Data) {
		t.Fatal("new retry changed persisted match capacity", err)
	}
}
