//go:build linux

package executor

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestIntrusionScalarMutationRequestHasOnlyFourFixedFieldsAndCanonicalValues(t *testing.T) {
	for _, item := range []struct {
		action string
		change intrusionScalarChange
	}{
		{"nftables", intrusionScalarChange{"maxretry", "5", "6"}},
		{"nftables", intrusionScalarChange{"findtime", "600", "660"}},
		{"nftables", intrusionScalarChange{"bantime", "3600", "3660"}},
		{"nftables", intrusionScalarChange{"port", "22", "22,2882"}},
		{"nftables-multiport", intrusionScalarChange{"port", "2882", "2883"}},
	} {
		args, err := intrusionScalarMutationArgs("123", "10000", item.action, item.change)
		if err != nil || len(args) != 10 || args[0] != "-I" || args[1] != "-B" || args[2] != "-c" || args[3] != intrusionScalarMutationScript || args[4] != "123" || args[5] != item.change.Key || args[7] != item.change.From || args[8] != item.change.To || args[9] != "10000" {
			t.Fatal("nonfixed helper request", err)
		}
		if item.change.Key != "port" && args[6] != "-" {
			t.Fatal("unused action leaked into limit request")
		}
	}
}

func TestIntrusionScalarMutationRequestRejectsCommandsAliasesRangesAndCapacityEscapes(t *testing.T) {
	for _, c := range []intrusionScalarChange{{"unban", "5", "6"}, {"actionreload", "5", "6"}, {"maxmatches", "5", "6"}, {"maxretry", "5", "5"}, {"maxretry", "5", "21"}, {"maxretry", "05", "6"}, {"findtime", "600", "661"}, {"findtime", "600", "0"}, {"bantime", "3600", "60"}, {"port", "22", "ssh"}, {"port", "22", "22:23"}, {"port", "22", "2882,22"}, {"port", "22", "22,22"}, {"port", "22", "0"}, {"port", "22", "65536"}, {"port", "22", "22;stop"}} {
		if _, err := intrusionScalarMutationArgs("123", "10000", "nftables", c); err == nil {
			t.Fatal("unsafe scalar grammar accepted", c.Key, c.To)
		}
	}
	for _, pid := range []string{"0", "1", "0123", "4194305", "123;stop"} {
		if _, err := intrusionScalarMutationArgs(pid, "10000", "nftables", intrusionScalarChange{"maxretry", "5", "6"}); err == nil {
			t.Fatal("bad process accepted")
		}
	}
	if _, err := intrusionScalarMutationArgs("123", "10000", "custom-action", intrusionScalarChange{"port", "22", "2882"}); err == nil {
		t.Fatal("foreign action accepted")
	}
}

func TestIntrusionScalarMutationReceiptRequiresCompleteOriginalIdentityAndNoAmbiguousOutcome(t *testing.T) {
	change := intrusionScalarChange{"maxretry", "5", "6"}
	for _, applied := range []bool{false, true} {
		v := intrusionScalarMutationReceipt{Format: 1, PID: "123", StartTicks: "10000", Field: "maxretry", Action: "-", From: "5", To: "6", Applied: applied, AlreadyTarget: !applied}
		raw, _ := json.Marshal(v)
		if _, err := intrusionScalarMutationDecode(append(raw, '\n'), "123", "10000", "nftables", change); err != nil {
			t.Fatal(err)
		}
	}
	v := intrusionScalarMutationReceipt{Format: 1, PID: "123", StartTicks: "10000", Field: "maxretry", Action: "-", From: "5", To: "6", Applied: true}
	raw, _ := json.Marshal(v)
	for _, bad := range []string{`{"format":0}`, string(raw) + `{}`, strings.Replace(string(raw), `"pid":"123"`, `"pid":"124"`, 1), strings.Replace(string(raw), `"to":"6"`, `"to":"7"`, 1), strings.Replace(string(raw), `"already_target":false`, `"already_target":true`, 1), strings.Replace(string(raw), `"applied":true,`, "", 1), strings.Replace(string(raw), `"format":1`, `"format":1,"FORMAT":1`, 1), strings.Replace(string(raw), `"format":1`, `"format":1,"script":"stop"`, 1)} {
		if _, err := intrusionScalarMutationDecode([]byte(bad), "123", "10000", "nftables", change); err == nil {
			t.Fatal("ambiguous or foreign receipt accepted")
		}
	}
}

func TestIntrusionScalarMutationPureWireGrammarNeverConnectsOrLoadsMain(t *testing.T) {
	code := `import ast,sys,pickle
tree=ast.parse(sys.stdin.read());wanted={'decode_reply','scalar_request','canonical_process_ticks'};nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign))or isinstance(n,ast.FunctionDef)and n.name in wanted or isinstance(n,ast.ClassDef)and n.name=='Primitives'];assert {n.name for n in nodes if isinstance(n,ast.FunctionDef)}==wanted;scope={'__name__':'pure_single_scalar_grammar'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-single-scalar-grammar>','exec'),scope);request=scope['scalar_request'];decode=scope['decode_reply']
assert request(['123','maxretry','-','5','6','10000'])==(123,['get','sshd','maxretry'],['set','sshd','maxretry','6'],int)
assert request(['123','port','nftables','22','22,2882','10000'])==(123,['get','sshd','action','nftables','port'],['set','sshd','action','nftables','port','22,2882'],str)
for args in (['123','unban','-','5','6'],['123','maxretry','-','5','5'],['123','maxretry','-','5','21'],['123','bantime','-','3600','60'],['123','findtime','-','600','601'],['123','port','nftables','22','ssh'],['123','port','nftables','22','22:23'],['0123','maxretry','-','5','6'],['123','port','custom','22','2882']):
 try:request([*args,'10000'])
 except Exception:pass
 else:raise AssertionError('noncanonical scalar request accepted')
assert decode(pickle.dumps((0,6)))==6
for raw in (b'cbuiltins\nset\n]R.',pickle.dumps((0,[]))+b'junk'):
 try:decode(raw)
 except Exception:pass
 else:raise AssertionError('executable or trailing reply accepted')
print('PASS pure scalar grammar only; no socket, SET, subprocess or service operation')`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionScalarMutationScript)
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), "PASS pure scalar grammar only") {
		t.Fatal(err, string(raw))
	}
}
