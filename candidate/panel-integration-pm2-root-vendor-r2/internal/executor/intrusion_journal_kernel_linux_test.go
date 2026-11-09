//go:build linux

package executor

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func intrusionTransactionDualKernel(t *testing.T, p intrusionJournalPlan, ports []int) []byte {
	t.Helper()
	var v map[string]any
	if json.Unmarshal(p.KernelBefore, &v) != nil {
		t.Fatal("fixture kernel")
	}
	intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.3"}
	var match any = float64(ports[0])
	if len(ports) > 1 {
		values := []any{}
		for _, p := range ports {
			values = append(values, float64(p))
		}
		match = map[string]any{"set": values}
	}
	intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = match
	var rule map[string]any
	json.Unmarshal(intrusionNftEncode(t, intrusionNftOwnRule(v)), &rule)
	rule["handle"] = float64(13)
	source := rule["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)
	source["left"] = map[string]any{"payload": map[string]any{"field": "saddr", "protocol": "ip6"}}
	source["right"] = "@" + p.BeforePolicy.IPv6Set
	rule["expr"].([]any)[2].(map[string]any)["reject"].(map[string]any)["type"] = "icmpv6"
	v["nftables"] = append(intrusionNftObjects(v), map[string]any{"set": map[string]any{"family": "inet", "table": p.BeforePolicy.Table, "name": p.BeforePolicy.IPv6Set, "handle": float64(12), "type": "ipv6_addr", "elem": []any{"2001:db8::2"}}}, map[string]any{"rule": rule})
	return intrusionNftEncode(t, v)
}

func intrusionTransactionDirectory(t *testing.T, raw []byte) []byte {
	t.Helper()
	var v map[string][]map[string]any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("kernel fixture")
	}
	objects := []map[string]any{}
	for _, o := range v["nftables"] {
		if _, ok := o["table"]; ok {
			objects = append(objects, o)
		}
	}
	return intrusionNftEncode(t, map[string]any{"nftables": objects})
}

func TestIntrusionTransactionKernelAllowsRealNewFamilyWithoutReplacingHistoricalHandlesOrIPs(t *testing.T) {
	p := intrusionJournalFixture(t)
	original, _ := json.Marshal(p)
	bans := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("2001:db8::2")}
	for _, ports := range [][]int{p.BeforePolicy.Ports, p.TargetPorts} {
		raw := intrusionTransactionDualKernel(t, p, ports)
		out, err := intrusionJournalKernelAccept(p, raw, nil, bans)
		if err != nil || out.State != "rules_observed" || !slices.Equal(out.Ports, ports) || len(out.StaticIdentity) != 64 {
			t.Fatal(out, err)
		}
		policy := p.BeforePolicy
		policy.Ports = out.Ports
		plan, err := planIntrusionNftPortChange(raw, intrusionPolicyScope(policy, bans), p.TargetPorts)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ports, p.TargetPorts) && (len(plan.RuleHandles) != 2 || !slices.Equal(plan.RuleHandles, []uint64{3, 13})) {
			t.Fatal("new current family not retained", plan)
		}
		for _, line := range plan.Statements {
			if strings.Contains(line, "127.0.0.") || strings.Contains(line, "2001:db8") || strings.Contains(line, "element") {
				t.Fatal("historical ban restoration authority")
			}
		}
	}
	after, _ := json.Marshal(p)
	if string(original) != string(after) {
		t.Fatal("original audit history repaired")
	}
}

func TestIntrusionTransactionKernelSupportsVerifiedLazyCreationWithoutInventingOrDeletingSets(t *testing.T) {
	for _, oldState := range []string{"table_absent", "scope_absent"} {
		t.Run(oldState, func(t *testing.T) {
			p := intrusionJournalAbsentFixture(t, oldState)
			raw := []byte(intrusionInspectionKernelFixture(t, p.BeforePolicy.Ports))
			var directory []byte
			if oldState == "table_absent" {
				directory = intrusionTransactionDirectory(t, raw)
			}
			out, err := intrusionJournalKernelAccept(p, raw, directory, nil)
			if err != nil || out.State != "rules_observed" || !slices.Equal(out.Ports, p.BeforePolicy.Ports) {
				t.Fatal(out, err)
			}
			deferred := intrusionNftEncode(t, intrusionLazySharedTable(t))
			if oldState == "table_absent" {
				directory = intrusionTransactionDirectory(t, deferred)
			}
			out, err = intrusionJournalKernelAccept(p, deferred, directory, nil)
			if err != nil || out.State != "scope_absent" || len(out.Ports) != 0 {
				t.Fatal(out, err)
			}
			if oldState == "table_absent" {
				out, err = intrusionJournalKernelAccept(p, nil, p.KernelDirectory, nil)
				if err != nil || out.State != "table_absent" || len(out.Ports) != 0 {
					t.Fatal(out, err)
				}
			}
		})
	}
}

func TestIntrusionTransactionKernelRejectsForeignOriginalPolicyAndUnverifiedDirectory(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"old-rule-handle": func(v map[string]any) { intrusionNftOwnRule(v)["handle"] = float64(90) },
		"old-set-handle":  func(v map[string]any) { intrusionNftOwnSet(v)["handle"] = float64(91) },
		"chain-handle":    func(v map[string]any) { intrusionNftChain(v)["handle"] = float64(92) },
		"third-port": func(v map[string]any) {
			intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2222)
		},
		"bypass": func(v map[string]any) {
			v["nftables"] = append(intrusionNftObjects(v), map[string]any{"rule": map[string]any{"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "handle": float64(94), "expr": []any{map[string]any{"accept": nil}}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			var v map[string]any
			json.Unmarshal(p.KernelBefore, &v)
			change(v)
			out, err := intrusionJournalKernelAccept(p, intrusionNftEncode(t, v), nil, []netip.Addr{netip.MustParseAddr("127.0.0.2")})
			if err == nil || !reflect.DeepEqual(out, intrusionTransactionKernel{}) {
				t.Fatal("foreign original policy adopted", out, err)
			}
		})
	}
	p := intrusionJournalAbsentFixture(t, "table_absent")
	raw := []byte(intrusionInspectionKernelFixture(t, p.BeforePolicy.Ports))
	directory := intrusionTransactionDirectory(t, raw)
	for _, bad := range [][]byte{nil, []byte(`{"nftables":[]}`), []byte(`{"nftables":[{"table":{"family":"inet","name":"f2b-table","handle":999}}]}`), []byte(`{"nftables":[{"table":{"family":"inet","name":"unexpected"}},{"table":{"family":"inet","name":"f2b-table"}}]}`)} {
		if _, err := intrusionJournalKernelAccept(p, raw, bad, nil); err == nil {
			t.Fatal("incomplete, conflicting or foreign directory adopted")
		}
	}
	if _, err := intrusionJournalKernelAccept(p, nil, directory, nil); err == nil {
		t.Fatal("present directory with missing table accepted")
	}
	if _, err := intrusionJournalKernelAccept(p, nil, p.KernelDirectory, []netip.Addr{netip.MustParseAddr("127.0.0.2")}); err == nil {
		t.Fatal("missing table used to hide active ban")
	}
}
