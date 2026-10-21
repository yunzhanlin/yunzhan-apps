//go:build linux

package executor

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestIntrusionNftPortPlanBothFamiliesNeverReturnsPartialBatch(t *testing.T) {
	value, scope := intrusionNftFixture(t)
	var rule map[string]any
	if e := json.Unmarshal(intrusionNftEncode(t, intrusionNftOwnRule(value)), &rule); e != nil {
		t.Fatal(e)
	}
	rule["handle"] = float64(13)
	match := rule["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)
	match["left"] = map[string]any{"payload": map[string]any{"field": "saddr", "protocol": "ip6"}}
	match["right"] = "@addr6-set-probe_sshd"
	rule["expr"].([]any)[2].(map[string]any)["reject"].(map[string]any)["type"] = "icmpv6"
	value["nftables"] = append(intrusionNftObjects(value), map[string]any{"set": map[string]any{"family": "inet", "table": "f2b-table", "name": "addr6-set-probe_sshd", "handle": float64(12), "type": "ipv6_addr", "elem": []any{"2001:db8::2"}}}, map[string]any{"rule": rule})
	scope.Banned = append(scope.Banned, netip.MustParseAddr("2001:db8::2"))
	plan, e := planIntrusionNftPortChange(intrusionNftEncode(t, value), scope, []int{2883})
	if e != nil || len(plan.Statements) != 2 || !slices.Equal(plan.RuleHandles, []uint64{3, 13}) || !strings.Contains(plan.Statements[1], "ip6 saddr @addr6-set-probe_sshd reject with icmpv6 type port-unreachable") {
		t.Fatal(plan, e)
	}
	rule["comment"] = "unregistered IPv6 policy annotation"
	plan, e = planIntrusionNftPortChange(intrusionNftEncode(t, value), scope, []int{2883})
	if e == nil || len(plan.Statements) != 0 || len(plan.RuleHandles) != 0 {
		t.Fatal("partial first-family batch escaped an error", plan, e)
	}
}

func TestIntrusionNftPortPlanOnlyReplacesExactOwnedHandle(t *testing.T) {
	value, scope := intrusionNftFixture(t)
	raw := intrusionNftEncode(t, value)
	plan, e := planIntrusionNftPortChange(raw, scope, []int{2883})
	if e != nil || len(plan.BeforeSHA256) != 64 || !slices.Equal(plan.RuleHandles, []uint64{3}) || !slices.Equal(plan.TargetPorts, []int{2883}) || len(plan.Statements) != 1 {
		t.Fatal(plan, e)
	}
	wanted := "replace rule inet f2b-table f2b-chain handle 3 tcp dport { 2883 } ip saddr @addr-set-probe_sshd reject with icmp type port-unreachable\n"
	if plan.Statements[0] != wanted {
		t.Fatal(plan.Statements[0])
	}
	for _, forbidden := range []string{"probe_other", "29999", "delete ", "flush ", "add element", "unban", "restart", "include", ";"} {
		if strings.Contains(plan.Statements[0], forbidden) {
			t.Fatal("plan widened scope", forbidden)
		}
	}
	if string(intrusionNftEncode(t, value)) != string(raw) {
		t.Fatal("planning modified original snapshot")
	}
}

func TestIntrusionNftPortPlanUnchangedPortsAreWriteFree(t *testing.T) {
	value, scope := intrusionNftFixture(t)
	plan, e := planIntrusionNftPortChange(intrusionNftEncode(t, value), scope, []int{2882})
	if e != nil || len(plan.BeforeSHA256) != 64 || len(plan.Statements) != 0 || len(plan.RuleHandles) != 0 {
		t.Fatal(plan, e)
	}
}

func TestIntrusionNftPortPlanRefusesForeignMetadataOrUnknownKernelState(t *testing.T) {
	for _, mode := range []string{"comment", "duplicate-rule", "stale-IP", "wrong-kernel-port", "injected-table"} {
		value, scope := intrusionNftFixture(t)
		switch mode {
		case "comment":
			intrusionNftOwnRule(value)["comment"] = "operator-owned metadata"
		case "duplicate-rule":
			value["nftables"] = append(intrusionNftObjects(value), map[string]any{"rule": intrusionNftOwnRule(value)})
		case "stale-IP":
			intrusionNftOwnSet(value)["elem"] = []any{"127.0.0.3"}
		case "wrong-kernel-port":
			scope.Ports = []int{22}
		case "injected-table":
			scope.Table = "f2b-table\nflush ruleset"
		}
		if plan, e := planIntrusionNftPortChange(intrusionNftEncode(t, value), scope, []int{2883}); e == nil || len(plan.Statements) > 0 {
			t.Fatal("unknown authority produced a plan", mode, plan, e)
		}
	}
}

func TestIntrusionNftPortPlanRejectsInvalidOrUnboundedTargetPorts(t *testing.T) {
	for _, name := range []string{"", "1table", "include", "flush", "table", "f2b-table;flush", "f2b\nrule", "f2b table", "f2b\"table", "f2b\\table"} {
		if intrusionNftWriteName(name) {
			t.Fatal("identifier became grammar", name)
		}
	}
	value, scope := intrusionNftFixture(t)
	raw := intrusionNftEncode(t, value)
	for _, ports := range [][]int{nil, {}, {0}, {65536}, {2883, 2882}, {2882, 2882}, make([]int, 17)} {
		if plan, e := planIntrusionNftPortChange(raw, scope, ports); e == nil || len(plan.Statements) > 0 {
			t.Fatal("bad target produced commands", ports, plan, e)
		}
	}
}
