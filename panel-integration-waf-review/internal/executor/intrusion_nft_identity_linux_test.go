//go:build linux

package executor

import (
	"net/netip"
	"testing"
)

func TestIntrusionNftPolicyIdentityAllowsCurrentBansNotHistoricalReplay(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	before, err := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope)
	if err != nil {
		t.Fatal(err)
	}
	intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.3"}
	// An expired address is replaced by a new, actually observed live ban.
	// The identity is NOT permission to resurrect the historical address.
	if _, err = intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope); err == nil {
		t.Fatal("stale runtime ban set accepted")
	}
	scope.Banned = []netip.Addr{netip.MustParseAddr("127.0.0.3")}
	after, err := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope)
	if err != nil || before != after {
		t.Fatal("legitimate live ban evolution treated as policy replacement", err)
	}
}

func TestIntrusionNftPolicyIdentityNormalizesOnlyVerifiedOwnedPortMatch(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	before, err := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope)
	if err != nil {
		t.Fatal(err)
	}
	intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2883)
	if _, err = intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope); err == nil {
		t.Fatal("unverified port scope accepted")
	}
	scope.Ports = []int{2883}
	after, err := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope)
	if err != nil || before != after {
		t.Fatal("transaction-owned port change altered static identity", err)
	}
	intrusionNftOwnRule(v)["handle"] = float64(33)
	drift, err := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), scope)
	if err != nil || drift == before {
		t.Fatal("different rule handle adopted", err)
	}
}

func TestIntrusionNftPolicyIdentityPreservesAllNonOwnedPolicyAndRejectsUnknownDynamics(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"chain-handle": func(v map[string]any) { intrusionNftChain(v)["handle"] = float64(90) },
		"rule-verdict": func(v map[string]any) { intrusionNftOwnRule(v)["expr"].([]any)[2] = map[string]any{"drop": nil} },
		"set-handle":   func(v map[string]any) { intrusionNftOwnSet(v)["handle"] = float64(91) },
		"rule-comment": func(v map[string]any) { intrusionNftOwnRule(v)["comment"] = "manual" },
	} {
		t.Run(name, func(t *testing.T) {
			v, s := intrusionNftFixture(t)
			before, e := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), s)
			if e != nil {
				t.Fatal(e)
			}
			mutate(v)
			after, e := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), s)
			if e == nil && before == after {
				t.Fatal("non-owned policy silently erased")
			}
		})
	}
	for name, elem := range map[string]any{"timeout": []any{map[string]any{"elem": "127.0.0.3", "expires": 30}}, "wrong-family": []any{"2001:db8::2"}, "duplicate": []any{"127.0.0.3", "127.0.0.3"}, "arbitrary-expression": map[string]any{"command": "flush ruleset"}} {
		t.Run(name, func(t *testing.T) {
			v, s := intrusionNftFixture(t)
			v["nftables"] = append(intrusionNftObjects(v), map[string]any{"set": map[string]any{"family": "inet", "table": s.Table, "name": "foreign_set", "handle": float64(91), "type": "ipv4_addr", "elem": elem}})
			if _, e := intrusionNftPolicyIdentity(intrusionNftEncode(t, v), s); e == nil {
				t.Fatal("unknown dynamic data erased")
			}
		})
	}
}
