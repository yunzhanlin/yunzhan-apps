package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func mustEgress(t *testing.T, current, retiring []Entry) EgressGuard {
	t.Helper()
	g, err := PlanEgressGuard(current, retiring, facts(), 991)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestEgressGuardExactBothGenerationProtocolIPAndPort(t *testing.T) {
	current, prior := fixture(), fixture()
	current.Revision++
	current.Nodes[1].Backup = true
	prior.Nodes[0].Address = "198.51.100.8:41003"
	udp := clone(current)
	udp.Name, udp.Protocol, udp.Port, udp.ProbePort = "udp.lb.invalid", "udp", 42001, 43001
	udp.UDPRequests, udp.UDPResponses = 1, 1
	g := mustEgress(t, []Entry{udp, current}, []Entry{prior})
	create, err := g.CreateRules()
	if err != nil || g.SHA256() == "" {
		t.Fatal(err)
	}
	for _, want := range []string{
		"create table inet panel_lbstream { comment \"panel-lbstream-v1 uid=991\"; }\n",
		"add chain inet panel_lbstream output { type filter hook output priority 10; policy accept; }\n",
		"meta skuid != 991 return\n",
		"ct state established ct direction reply tcp sport 42000 accept\n",
		"ct state established ct direction reply tcp sport 43000 accept\n",
		"ct state established ct direction reply tcp sport 43001 accept\n",
		"ct state established ct direction reply udp sport 42001 accept\n",
		"ip daddr 192.0.2.10 tcp dport 41001 accept\n",
		"ip daddr 198.51.100.8 tcp dport 41003 accept\n",
		"ip6 daddr 2001:db8::2 tcp dport 41002 accept\n",
		"ip daddr 192.0.2.10 udp dport 41001 accept\n",
		"ip6 daddr 2001:db8::2 udp dport 41002 accept\n",
	} {
		if !bytes.Contains(create, []byte(want)) {
			t.Fatal("missing exact predicate", want)
		}
	}
	if !bytes.HasSuffix(create, []byte("add rule inet panel_lbstream output meta skuid 991 drop comment \"panel-lbstream-policy-v1 sha256="+g.SHA256()+"\"\n")) || bytes.Count(create, []byte("tcp sport 43000 accept\n")) != 1 {
		t.Fatal("last deny or deduplication changed")
	}
	for _, forbidden := range []string{"related", "0.0.0.0/0", "::/0", "established accept", "flush ruleset", "delete table", "udp sport 43000", "counter", "jump", "include", "exec", "; accept"} {
		if bytes.Contains(create, []byte(forbidden)) {
			t.Fatal("unbounded or unrelated authority", forbidden)
		}
	}
	again := mustEgress(t, []Entry{current, udp}, []Entry{prior})
	againRaw, _ := again.CreateRules()
	if !bytes.Equal(create, againRaw) || g.SHA256() != again.SHA256() {
		t.Fatal("input ordering changed canonical policy")
	}
	replacement, err := g.ReplacementRules()
	if err != nil || !bytes.HasPrefix(replacement, []byte("flush chain inet panel_lbstream output\n")) || bytes.Count(replacement, []byte("flush chain inet panel_lbstream output\n")) != 1 || bytes.Contains(replacement, []byte(" table ")) || bytes.Contains(replacement, []byte("add chain")) {
		t.Fatal("replacement changes another chain/table", err)
	}
	if !bytes.Equal(create[bytes.Index(create, []byte("add rule ")):], replacement[bytes.Index(replacement, []byte("add rule ")):]) {
		t.Fatal("replacement does not rebuild complete exact policy")
	}
}

func TestEgressGuardRejectsMissingFactsRoleReuseAndJointBudget(t *testing.T) {
	for _, uid := range []uint32{0, 33, 99, 1000, 65535, ^uint32(0)} {
		if g, err := PlanEgressGuard([]Entry{fixture()}, nil, facts(), uid); err != ErrEgressGuard || !reflect.DeepEqual(g, EgressGuard{}) {
			t.Fatal("unsafe UID or partial guard", uid, err)
		}
	}
	for _, uid := range []uint32{100, 999} {
		if _, err := PlanEgressGuard([]Entry{fixture()}, nil, facts(), uid); err != nil {
			t.Fatal("valid system UID boundary refused", uid, err)
		}
	}
	for _, scenario := range []string{"memory", "missing-control", "occupied", "custom-control", "cross-role", "cross-probe", "cross-cycle", "bad-prior"} {
		t.Run(scenario, func(t *testing.T) {
			current, prior, ctx := fixture(), fixture(), facts()
			current.Revision++
			switch scenario {
			case "memory":
				ctx.MemoryBudgetBytes = 2*(FixedBytesPerEntry+int64(current.MaxSessions)*BytesPerSession) - 1
			case "missing-control":
				ctx.PanelControlPorts = nil
			case "occupied":
				ctx.OccupiedTCPPorts = []int{current.ProbePort}
			case "custom-control":
				ctx.PanelControlPorts = append(ctx.PanelControlPorts, 41001)
			case "cross-role":
				current.Port, current.ProbePort = 44000, prior.Port
			case "cross-probe":
				current.Port, current.ProbePort = 44000, 45000
				current.Nodes[0].Address = "127.0.0.1:43000"
			case "cross-cycle":
				current.Name, current.Port, current.ProbePort = "other.lb.invalid", 44000, 45000
				prior.Nodes[0].Address = "127.0.0.1:44000"
				current.Nodes[0].Address = "127.0.0.1:42000"
			case "bad-prior":
				prior.Nodes[1].Address = "169.254.169.254:80"
			}
			g, err := PlanEgressGuard([]Entry{current}, []Entry{prior}, ctx, 991)
			if err != ErrEgressGuard || !reflect.DeepEqual(g, EgressGuard{}) {
				t.Fatal("partial/unsafe policy accepted", err)
			}
		})
	}
	tombstone := fixture()
	tombstone.Revision, tombstone.Removed = 2, true
	g := mustEgress(t, []Entry{tombstone}, []Entry{fixture()})
	prior := mustEgress(t, []Entry{fixture()}, nil)
	if g.SHA256() != prior.SHA256() {
		t.Fatal("last-entry removal lost draining backend policy")
	}
	idle := mustEgress(t, []Entry{tombstone}, nil)
	raw, err := idle.CreateRules()
	if err != nil || bytes.Contains(raw, []byte(" accept\n")) || bytes.Count(raw, []byte("add rule ")) != 2 {
		t.Fatal("stopped generation allows stale service egress", err)
	}
	for _, guard := range []EgressGuard{{}, {document: prior.document, raw: prior.raw, sha256: strings.Repeat("f", 64)}} {
		if guard.SHA256() != "" {
			t.Fatal("forged guard digest accepted")
		}
		if _, err := guard.CreateRules(); err != ErrEgressGuard {
			t.Fatal("invalid guard emitted create bytes")
		}
		if _, err := guard.ReplacementRules(); err != ErrEgressGuard {
			t.Fatal("invalid guard emitted replace bytes")
		}
		if _, err := guard.Inspect([]byte(`{"nftables":[]}`)); err != ErrEgressGuard {
			t.Fatal("invalid guard emitted an observation")
		}
	}
}

// The shape comes from a complete nft -s -j observation in an isolated native
// namespace. Each acceptance predicate is constructed independently of the
// production AST writer, then a real nft observation is tested separately.
func egressFixtureJSON(t *testing.T, g EgressGuard) []byte {
	t.Helper()
	objects := []any{
		map[string]any{"metainfo": map[string]any{"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}},
		map[string]any{"table": map[string]any{"family": "inet", "name": "panel_lbstream", "handle": 1, "comment": "panel-lbstream-v1 uid=" + strconv.FormatUint(uint64(g.document.UID), 10)}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "panel_lbstream", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 10, "policy": "accept"}},
	}
	match := func(op, kind, key string, right any) any {
		return map[string]any{"match": map[string]any{"op": op, "left": map[string]any{kind: map[string]any{"key": key}}, "right": right}}
	}
	payload := func(protocol, field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right}}
	}
	rule := func(expr []any) {
		objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": "panel_lbstream", "chain": "output", "handle": len(objects) - 1, "expr": expr}})
	}
	rule([]any{match("!=", "meta", "skuid", g.document.UID), map[string]any{"return": nil}})
	for _, listener := range g.document.Listeners {
		rule([]any{match("in", "ct", "state", "established"), match("==", "ct", "direction", "reply"), payload(listener.Protocol, "sport", listener.Port), map[string]any{"accept": nil}})
	}
	for _, backend := range g.document.Backends {
		family := "ip"
		if strings.Contains(backend.Address, ":") {
			family = "ip6"
		}
		rule([]any{payload(family, "daddr", backend.Address), payload(backend.Protocol, "dport", backend.Port), map[string]any{"accept": nil}})
	}
	rule([]any{match("==", "meta", "skuid", g.document.UID), map[string]any{"drop": nil}})
	objects[len(objects)-1].(map[string]any)["rule"].(map[string]any)["comment"] = "panel-lbstream-policy-v1 sha256=" + g.SHA256()
	raw, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEgressObservationExactRulesAndNoUnknownObjects(t *testing.T) {
	g := mustEgress(t, []Entry{fixture()}, nil)
	raw := egressFixtureJSON(t, g)
	got, err := g.Inspect(raw)
	if err != nil || got.PolicySHA256 != g.SHA256() || got.TableHandle != 1 || got.ChainHandle != 1 || !reflect.DeepEqual(got.RuleHandles, []uint64{2, 3, 4, 5, 6, 7}) {
		t.Fatal("complete real-shaped observation refused", got, err)
	}
	changes := map[string][2]string{
		"UID": {`"right":991`, `"right":992`}, "UID-op": {`"op":"!="`, `"op":"=="`},
		"reply": {`"right":"reply"`, `"right":"original"`}, "state": {`"right":"established"`, `"right":"related"`},
		"source": {`"field":"sport"`, `"field":"dport"`}, "front-port": {`"right":42000`, `"right":42001`},
		"backend-port": {`"right":41001`, `"right":41003`}, "backend-IP": {`"right":"192.0.2.10"`, `"right":"192.0.2.11"`},
		"protocol": {`"protocol":"tcp"`, `"protocol":"udp"`}, "family": {`"family":"inet"`, `"family":"ip"`},
		"priority": {`"prio":10`, `"prio":9`}, "hook": {`"hook":"output"`, `"hook":"input"`},
		"chain-policy": {`"policy":"accept"`, `"policy":"drop"`}, "chain-name": {`"name":"output"`, `"name":"foreign"`},
		"table-name": {`"name":"panel_lbstream"`, `"name":"foreign"`}, "drop": {`"drop":null`, `"accept":null`},
		"early-accept": {`"return":null`, `"accept":null`}, "foreign-comment": {g.SHA256(), strings.Repeat("f", 64)},
		"duplicate-handle": {`"handle":7`, `"handle":2`}, "chain-handle-as-rule": {`"handle":7`, `"handle":1`},
		"zero-handle": {`"handle":7`, `"handle":0`}, "handle-string": {`"handle":7`, `"handle":"7"`},
		"handle-exponent": {`"handle":7`, `"handle":7e0`}, "schema": {`"json_schema_version":1`, `"json_schema_version":2`},
		"counter":         {`"expr":[`, `"expr":[{"counter":{"packets":0,"bytes":0}},`},
		"duplicate-null":  {`"drop":null`, `"drop":null,"drop":null`},
		"duplicate-root":  {`{"nftables":`, `{"nftables":[],"nftables":`},
		"duplicate-match": {`"op":"in"`, `"op":"in","op":"in"`},
		"extra-root":      {`{"nftables":`, `{"verified":true,"nftables":`},
		"extra-table":     {`"table":{"comment":`, `"table":{"flags":["dormant"],"comment":`},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			mutated := bytes.Replace(raw, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(mutated, raw) {
				t.Fatal("test did not change observation")
			}
			if got, err := g.Inspect(mutated); err != ErrEgressGuard || !reflect.DeepEqual(got, EgressGuardObservation{}) {
				t.Fatal("changed kernel policy accepted", got, err)
			}
		})
	}
	for name, mutate := range map[string]func([]any) []any{
		"unscoped-final-deny": func(v []any) []any {
			v[len(v)-1].(map[string]any)["rule"].(map[string]any)["expr"] = []any{map[string]any{"drop": nil}}
			return v
		},
		"wrong-final-deny-UID": func(v []any) []any {
			expr := v[len(v)-1].(map[string]any)["rule"].(map[string]any)["expr"].([]any)
			expr[0].(map[string]any)["match"].(map[string]any)["right"] = 992
			return v
		},
		"negative-final-deny-UID": func(v []any) []any {
			expr := v[len(v)-1].(map[string]any)["rule"].(map[string]any)["expr"].([]any)
			expr[0].(map[string]any)["match"].(map[string]any)["op"] = "!="
			return v
		},
		"missing-policy-comment": func(v []any) []any {
			delete(v[len(v)-1].(map[string]any)["rule"].(map[string]any), "comment")
			return v
		},
		"comment-on-another-rule": func(v []any) []any {
			v[3].(map[string]any)["rule"].(map[string]any)["comment"] = "panel-lbstream-policy-v1 sha256=" + g.SHA256()
			return v
		},
		"extra-chain":  func(v []any) []any { return append(v, v[2]) },
		"missing-rule": func(v []any) []any { return append(v[:4], v[5:]...) },
		"reorder-rule": func(v []any) []any { v[4], v[5] = v[5], v[4]; return v },
		"set":          func(v []any) []any { v[3] = map[string]any{"set": map[string]any{"name": "foreign"}}; return v },
		"accept-only": func(v []any) []any {
			v[4].(map[string]any)["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
			return v
		},
	} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc["nftables"] = mutate(doc["nftables"].([]any))
			changed, _ := json.Marshal(doc)
			if _, err := g.Inspect(changed); err != ErrEgressGuard {
				t.Fatal("unknown or incomplete observation accepted")
			}
		})
	}
}

func TestEgressObservationParserBoundsDuplicatesAndCanonicalNumbers(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "{}", "true", "{", `[1,]`, `{"x":null,"x":null}`, `{"x":{"y":1,"y":1}}`, `{"x":[{"y":false,"y":true}]}`, `{"x":-1}`, `{"x":1.0}`, `{"x":1e0}`, `{"x":-0}`, `{"x":9223372036854775808}`, `{"x":"bad\nline"}`, `{"x":"bad\u0000line"}`, `{"x":1}{}`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18), `{"` + strings.Repeat("x", 129) + `":0}`, `{"x":"` + strings.Repeat("x", 257) + `"}`} {
		if _, err := egressJSON([]byte(raw)); err != ErrEgressGuard {
			// The generic parser may parse ordinary scalars/empty objects. The
			// closed complete-table inspector must still refuse them below.
			if raw != "null" && raw != "[]" && raw != "{}" && raw != "true" {
				t.Fatalf("unsafe JSON parser accepted %q", raw)
			}
		}
		g := mustEgress(t, nil, nil)
		if _, err := g.Inspect([]byte(raw)); err != ErrEgressGuard {
			t.Fatal("incomplete JSON observation accepted")
		}
	}
	if _, err := egressJSON(bytes.Repeat([]byte(" "), MaxEgressObservationBytes+1)); err != ErrEgressGuard {
		t.Fatal("unbounded observation accepted")
	}
	if _, err := egressJSON([]byte(strings.Repeat("[", 16) + "0" + strings.Repeat("]", 16))); err != nil {
		t.Fatal("exact nesting limit rejected")
	}
}

func TestEgressMaximumAdmissibleTwoGenerationObservationFitsBounds(t *testing.T) {
	current, prior := make([]Entry, 127), make([]Entry, 127)
	for i := range current {
		for generation, entries := range [][]Entry{current, prior} {
			e := fixture()
			e.Name, e.Revision, e.Port, e.ProbePort, e.MaxSessions = fmt.Sprintf("a%d.lb.invalid", i), int64(2-generation), 42000+i, 43000+i, 16
			e.Nodes = nil
			for node := 0; node < 16; node++ {
				e.Nodes = append(e.Nodes, Node{Address: "192.0.2.10:" + strconv.Itoa(1024+generation*2048+i*16+node), Weight: 1})
			}
			entries[i] = e
		}
	}
	ctx := facts()
	ctx.MemoryBudgetBytes = MaxMemoryBudget
	g, err := PlanEgressGuard(current, prior, ctx, 991)
	if err != nil {
		t.Fatal(err)
	}
	raw := egressFixtureJSON(t, g)
	if _, err := g.Inspect(raw); err != nil || len(raw) >= MaxEgressObservationBytes {
		t.Fatalf("admissible complete two-generation table cannot be inspected: %d bytes, %v", len(raw), err)
	}
	t.Logf("two generations: entries=%d backends=%d observed_bytes=%d", len(current)+len(prior), len(g.document.Backends), len(raw))
}
