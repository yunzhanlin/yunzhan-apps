//go:build linux

package executor

import (
	_ "embed"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

//go:embed testdata/intrusion-nft-reload-1.0.2.json
var intrusionNftReloadFixture []byte

func intrusionNftFixture(t *testing.T) (map[string]any, intrusionNftScope) {
	t.Helper()
	var source map[string]any
	if e := json.Unmarshal(intrusionNftReloadFixture, &source); e != nil {
		t.Fatal(e)
	}
	if source["source_proof_sha256"] != "45383d506fcf10da1be31c865c8f0bb0d13cd8c2e2dc5875c12be60cbca8ff34" || source["isolated_file_backend_NOT_installed_journald"] != true {
		t.Fatal("native observation boundary lost")
	}
	return source["before"].(map[string]any), intrusionNftScope{Table: "f2b-table", Chain: "f2b-chain", IPv4Set: "addr-set-probe_sshd", IPv6Set: "addr6-set-probe_sshd", Ports: []int{2882}, Banned: []netip.Addr{netip.MustParseAddr("127.0.0.2")}}
}
func intrusionNftEncode(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func intrusionNftObjects(v map[string]any) []any { return v["nftables"].([]any) }
func intrusionNftOwnSet(v map[string]any) map[string]any {
	for _, item := range intrusionNftObjects(v) {
		m := item.(map[string]any)
		if s, ok := m["set"].(map[string]any); ok && s["name"] == "addr-set-probe_sshd" {
			return s
		}
	}
	panic("fixture set missing")
}
func intrusionNftOwnRule(v map[string]any) map[string]any {
	for _, item := range intrusionNftObjects(v) {
		m := item.(map[string]any)
		if r, ok := m["rule"].(map[string]any); ok && r["handle"] == float64(3) {
			return r
		}
	}
	panic("fixture rule missing")
}
func intrusionNftChain(v map[string]any) map[string]any {
	for _, item := range intrusionNftObjects(v) {
		m := item.(map[string]any)
		if r, ok := m["chain"].(map[string]any); ok {
			return r
		}
	}
	panic("fixture chain missing")
}

func TestIntrusionNftActualReloadObservationCannotMasqueradeAsNewKernelPorts(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	out, e := inspectIntrusionNftScope(intrusionNftEncode(t, v), scope)
	if e != nil || !out.Verified || !out.IPv4 || out.IPv6 || out.ActiveBans != 1 {
		t.Fatal(out, e)
	}
	var source struct{ After json.RawMessage }
	if e = json.Unmarshal(intrusionNftReloadFixture, &source); e != nil {
		t.Fatal(e)
	}
	scope.Ports = []int{2883}
	if out, e = inspectIntrusionNftScope(source.After, scope); e == nil || out.Verified {
		t.Fatal("new property accepted stale actual kernel rule", out, e)
	}
	scope.Ports = []int{2882}
	if out, e = inspectIntrusionNftScope(source.After, scope); e != nil || !out.Verified {
		t.Fatal("original kernel observation was rewritten", out, e)
	}
}

func TestIntrusionNftBothAddressFamiliesAndExactNumericPortSets(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	own := intrusionNftOwnRule(v)
	own["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = map[string]any{"set": []any{float64(2883), float64(2882)}}
	var clone map[string]any
	if e := json.Unmarshal(intrusionNftEncode(t, own), &clone); e != nil {
		t.Fatal(e)
	}
	clone["handle"] = float64(13)
	match := clone["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)
	match["left"] = map[string]any{"payload": map[string]any{"field": "saddr", "protocol": "ip6"}}
	match["right"] = "@addr6-set-probe_sshd"
	clone["expr"].([]any)[2].(map[string]any)["reject"].(map[string]any)["type"] = "icmpv6"
	v["nftables"] = append(intrusionNftObjects(v), map[string]any{"set": map[string]any{"family": "inet", "table": "f2b-table", "name": "addr6-set-probe_sshd", "handle": float64(12), "type": "ipv6_addr", "elem": []any{"2001:db8::2"}}}, map[string]any{"rule": clone})
	scope.Ports = []int{2882, 2883}
	scope.Banned = append(scope.Banned, netip.MustParseAddr("2001:db8::2"))
	out, e := inspectIntrusionNftScope(intrusionNftEncode(t, v), scope)
	if e != nil || !out.Verified || !out.IPv4 || !out.IPv6 || out.ActiveBans != 2 {
		t.Fatal(out, e)
	}
	match["left"] = map[string]any{"payload": map[string]any{"field": "saddr", "protocol": "ip"}}
	if out, e = inspectIntrusionNftScope(intrusionNftEncode(t, v), scope); e == nil || out.Verified {
		t.Fatal("IPv6 set attached to IPv4 matcher accepted", out, e)
	}
}

func TestIntrusionNftUnknownOrForeignKernelPolicyNeverReportsVerified(t *testing.T) {
	for name, change := range map[string]func(map[string]any, *intrusionNftScope){
		"wrong-priority": func(v map[string]any, s *intrusionNftScope) { intrusionNftChain(v)["prio"] = float64(0) },
		"wrong-hook":     func(v map[string]any, s *intrusionNftScope) { intrusionNftChain(v)["hook"] = "forward" },
		"extra-port": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnRule(v)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = map[string]any{"set": []any{float64(80), float64(2882)}}
		},
		"missing-ban": func(v map[string]any, s *intrusionNftScope) { intrusionNftOwnSet(v)["elem"] = []any{} },
		"stale-extra-ban": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.2", "127.0.0.5"}
		},
		"duplicate-ban": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnSet(v)["elem"] = []any{"127.0.0.2", "127.0.0.2"}
		},
		"set-timeout":    func(v map[string]any, s *intrusionNftScope) { intrusionNftOwnSet(v)["timeout"] = float64(600) },
		"wrong-set-type": func(v map[string]any, s *intrusionNftScope) { intrusionNftOwnSet(v)["type"] = "ipv6_addr" },
		"unknown-source-range": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnSet(v)["elem"] = []any{map[string]any{"prefix": map[string]any{"addr": "127.0.0.0", "len": 24}}}
		},
		"accept-verdict": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnRule(v)["expr"].([]any)[2] = map[string]any{"accept": nil}
		},
		"jump-verdict": func(v map[string]any, s *intrusionNftScope) {
			intrusionNftOwnRule(v)["expr"].([]any)[2] = map[string]any{"jump": map[string]any{"target": "foreign"}}
		},
		"extra-unverified-match": func(v map[string]any, s *intrusionNftScope) {
			r := intrusionNftOwnRule(v)
			r["expr"] = append([]any{map[string]any{"counter": map[string]any{"packets": float64(1), "bytes": float64(100)}}}, r["expr"].([]any)...)
		},
		"duplicate-rule": func(v map[string]any, s *intrusionNftScope) {
			var clone map[string]any
			if e := json.Unmarshal(intrusionNftEncode(t, intrusionNftOwnRule(v)), &clone); e != nil {
				t.Fatal(e)
			}
			clone["handle"] = float64(19)
			v["nftables"] = append(intrusionNftObjects(v), map[string]any{"rule": clone})
		},
		"earlier-bypass": func(v map[string]any, s *intrusionNftScope) {
			bypass := map[string]any{"rule": map[string]any{"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "handle": float64(20), "expr": []any{map[string]any{"accept": nil}}}}
			v["nftables"] = append([]any{bypass}, intrusionNftObjects(v)...)
		},
		"unsorted-target":  func(v map[string]any, s *intrusionNftScope) { s.Ports = []int{2883, 2882} },
		"duplicate-target": func(v map[string]any, s *intrusionNftScope) { s.Ports = []int{2882, 2882} },
		"zone-ID": func(v map[string]any, s *intrusionNftScope) {
			s.Banned = []netip.Addr{netip.MustParseAddr("fe80::2%eth0")}
		},
		"duplicate-observed-IP": func(v map[string]any, s *intrusionNftScope) { s.Banned = append(s.Banned, s.Banned[0]) },
		"foreign-table":         func(v map[string]any, s *intrusionNftScope) { s.Table = "another-table" },
	} {
		t.Run(name, func(t *testing.T) {
			v, scope := intrusionNftFixture(t)
			change(v, &scope)
			out, e := inspectIntrusionNftScope(intrusionNftEncode(t, v), scope)
			if e == nil || out.Verified {
				t.Fatal("unverified kernel policy accepted", out, e)
			}
		})
	}
}

func TestIntrusionNftDuplicateTruncatedAndOversizedJSONFailsClosed(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	valid := string(intrusionNftEncode(t, v))
	for _, raw := range []string{valid + "{}", valid[:len(valid)-1], strings.Replace(valid, "\"nftables\":", "\"nftables\":[],\"nftables\":", 1), strings.Replace(valid, "\"nftables\":", "\"NFTABLES\":", 1), strings.Repeat(" ", 24577), "{}", "{\"nftables\":null}"} {
		if out, e := inspectIntrusionNftScope([]byte(raw), scope); e == nil || out.Verified {
			t.Fatal("ambiguous kernel output accepted", out, e)
		}
	}
}
