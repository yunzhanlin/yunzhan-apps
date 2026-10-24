//go:build linux

package executor

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestIntrusionJournalLiveRecoveryPreservesCurrentBansAndNeverResurrectsExpiredAddress(t *testing.T) {
	p := intrusionJournalFixture(t)
	var v map[string]any
	if err := json.Unmarshal(p.KernelBefore, &v); err != nil {
		t.Fatal(err)
	}
	intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.3"}
	intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2882)
	bans := []netip.Addr{netip.MustParseAddr("127.0.0.3")}
	plan, err := intrusionJournalLivePortPlan(p, intrusionNftEncode(t, v), bans, "rolled_back")
	if err != nil || len(plan.Statements) != 1 {
		t.Fatal(plan, err)
	}
	command := strings.Join(plan.Statements, "")
	if !strings.Contains(command, "handle 3 tcp dport { 22 }") || strings.Contains(command, "127.0.0.") || strings.Contains(command, "element") || strings.Contains(command, "flush") || strings.Contains(command, "restart") {
		t.Fatal("recovery has authority outside owned rule ports", command)
	}
	if _, err = intrusionJournalLivePortPlan(p, intrusionNftEncode(t, v), []netip.Addr{netip.MustParseAddr("127.0.0.2")}, "rolled_back"); err == nil {
		t.Fatal("stale historical ban list replaced current observation")
	}
}

func TestIntrusionJournalLiveRecoveryRejectsForeignPolicyAndNonTransactionalPorts(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"foreign-handle":  func(v map[string]any) { intrusionNftOwnRule(v)["handle"] = float64(90) },
		"foreign-verdict": func(v map[string]any) { intrusionNftOwnRule(v)["expr"].([]any)[2] = map[string]any{"drop": nil} },
		"foreign-port": func(v map[string]any) {
			intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(9999)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			var v map[string]any
			if err := json.Unmarshal(p.KernelBefore, &v); err != nil {
				t.Fatal(err)
			}
			mutate(v)
			plan, err := intrusionJournalLivePortPlan(p, intrusionNftEncode(t, v), []netip.Addr{netip.MustParseAddr("127.0.0.2")}, "rolled_back")
			if err == nil || len(plan.Statements) != 0 {
				t.Fatal("foreign state became recovery authority", plan, err)
			}
		})
	}
}

func TestIntrusionJournalLivePlanBeforeOrAfterNoOpNeverRestartsJail(t *testing.T) {
	p := intrusionJournalFixture(t)
	bans := []netip.Addr{netip.MustParseAddr("127.0.0.2")}
	plan, err := intrusionJournalLivePortPlan(p, p.KernelBefore, bans, "rolled_back")
	if err != nil || len(plan.Statements) != 0 {
		t.Fatal("known before state was needlessly changed", plan, err)
	}
	plan, err = intrusionJournalLivePortPlan(p, p.KernelBefore, bans, "committed")
	if err != nil || len(plan.Statements) != 1 || !strings.Contains(plan.Statements[0], "{ 2882 }") {
		t.Fatal(plan, err)
	}
	if plan, err = intrusionJournalLivePortPlan(p, p.KernelBefore, bans, "install"); err == nil || len(plan.Statements) != 0 {
		t.Fatal("arbitrary target state authorized", plan, err)
	}
}
