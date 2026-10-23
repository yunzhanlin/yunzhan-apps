//go:build linux

package executor

import (
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestIntrusionPortTemplateArgumentsContainOnlyTypedOriginalInputsNeverScripts(t *testing.T) {
	for _, field := range []string{"actionstart", "actionflush"} {
		for _, reverse := range []bool{false, true} {
			name := field + "-forward"
			if reverse {
				name = field + "-reverse"
			}
			t.Run(name, func(t *testing.T) {
				p := intrusionJournalFixture(t)
				after, err := intrusionPortRecipeTarget(p)
				if err != nil {
					t.Fatal(err)
				}
				change := intrusionPortRecipeChange{Field: field, From: p.ActionBefore.Values[field], To: after[field]}
				old, next := "22", "2882"
				if reverse {
					change.From, change.To = change.To, change.From
					old, next = next, old
				}
				args, err := intrusionPortTemplateMutationArgs(p, change)
				if err != nil || len(args) != 13 || !slices.Equal(args[:4], []string{"-I", "-B", "-c", intrusionPortTemplateMutationScript}) || !slices.Equal(args[4:], []string{p.ProcessBefore, field, p.BeforePolicy.Action, "nft", p.BeforePolicy.Table, p.BeforePolicy.Chain, old, next, p.ProcessStartBefore}) {
					t.Fatal("nonfixed typed template request", err)
				}
				for _, arg := range args[4:] {
					if strings.ContainsAny(arg, "\n\r\x00") || arg == change.From || arg == change.To {
						t.Fatal("action body leaked into typed helper arguments")
					}
				}
			})
		}
	}
}

func TestIntrusionPortTemplateArgumentsRejectForeignBodiesFieldsAndInvalidOriginals(t *testing.T) {
	for _, kind := range []string{"actionban", "port", "foreign-from", "foreign-to", "same", "unknown-format", "unknown-table", "extra-init"} {
		t.Run(kind, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			after, err := intrusionPortRecipeTarget(p)
			if err != nil {
				t.Fatal(err)
			}
			change := intrusionPortRecipeChange{Field: "actionstart", From: p.ActionBefore.Values["actionstart"], To: after["actionstart"]}
			switch kind {
			case "actionban", "port":
				change.Field = kind
			case "foreign-from":
				change.From += "; external-command"
			case "foreign-to":
				change.To += "; external-command"
			case "same":
				change.To = change.From
			case "unknown-format":
				p.Format = 2
			case "unknown-table":
				p.BeforePolicy.Table = "another_table"
			case "extra-init":
				p.ActionBefore.Properties = append(p.ActionBefore.Properties, "type")
				slices.Sort(p.ActionBefore.Properties)
				p.ActionBefore.Values["type"] = "multiport"
			}
			if _, err := intrusionPortTemplateMutationArgs(p, change); err == nil {
				t.Fatal("unqualified template authority accepted", kind)
			}
		})
	}
}

func TestIntrusionPortTemplateReceiptRequiresExactCanonicalHashedIdentity(t *testing.T) {
	p := intrusionJournalFixture(t)
	after, err := intrusionPortRecipeTarget(p)
	if err != nil {
		t.Fatal(err)
	}
	c := intrusionPortRecipeChange{Field: "actionstart", From: p.ActionBefore.Values["actionstart"], To: after["actionstart"]}
	v := intrusionPortTemplateReceipt{Format: 1, PID: p.ProcessBefore, StartTicks: p.ProcessStartBefore, Field: c.Field, Action: p.BeforePolicy.Action, FromSHA256: core.Hash(c.From), ToSHA256: core.Hash(c.To), Applied: true}
	for _, applied := range []bool{false, true} {
		v.Applied, v.AlreadyTarget = applied, !applied
		raw, _ := json.Marshal(v)
		if _, err := intrusionPortTemplateMutationDecode(append(raw, '\n'), p, c); err != nil {
			t.Fatal(err)
		}
	}
	v.Applied, v.AlreadyTarget = true, false
	raw, _ := json.Marshal(v)
	for _, bad := range []string{`{"format":0}`, string(raw) + `{}`, strings.Replace(string(raw), `"pid":"123"`, `"pid":"124"`, 1), strings.Replace(string(raw), core.Hash(c.From), strings.Repeat("a", 64), 1), strings.Replace(string(raw), core.Hash(c.To), strings.ToUpper(core.Hash(c.To)), 1), strings.Replace(string(raw), `"already_target":false`, `"already_target":true`, 1), strings.Replace(string(raw), `"applied":true,`, "", 1), strings.Replace(string(raw), `"format":1`, `"format":1,"FORMAT":1`, 1), strings.Replace(string(raw), `"format":1`, `"format":1,"force":true`, 1)} {
		if _, err := intrusionPortTemplateMutationDecode([]byte(bad), p, c); err == nil {
			t.Fatal("ambiguous, incomplete or foreign template receipt accepted")
		}
	}
}

func TestIntrusionPortTemplatePureRendererExactlyMatchesGoStockAndCannotAcceptScripts(t *testing.T) {
	type vector struct {
		Args   []string `json:"args"`
		Before string   `json:"before"`
		After  string   `json:"after"`
	}
	vectors := []vector{}
	p := intrusionJournalFixture(t)
	for _, program := range []string{"nft", "/usr/sbin/nft", "/usr/bin/nft"} {
		for _, field := range []string{"actionstart", "actionflush"} {
			before, err := intrusionStockActionValues(p.BeforePolicy, program, p.ActionBefore.Values["chain"])
			if err != nil {
				t.Fatal(err)
			}
			policy := p.BeforePolicy
			policy.Ports = []int{22, 2882}
			after, err := intrusionStockActionValues(policy, program, p.ActionBefore.Values["chain"])
			if err != nil {
				t.Fatal(err)
			}
			vectors = append(vectors, vector{Args: []string{"123", field, "nftables", program, policy.Table, policy.Chain, "22", "22,2882", p.ProcessStartBefore}, Before: before[field], After: after[field]})
		}
	}
	payload, _ := json.Marshal(map[string]any{"source": intrusionPortTemplateMutationScript, "vectors": vectors})
	code := `import ast,json,pickle,sys
p=json.loads(sys.stdin.read());tree=ast.parse(p['source']);wanted={'identifier','port_string','render_template','template_request','decode_reply','canonical_process_ticks'};nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign))or isinstance(n,ast.FunctionDef)and n.name in wanted or isinstance(n,ast.ClassDef)and n.name=='Primitives'];assert {n.name for n in nodes if isinstance(n,ast.FunctionDef)}==wanted;scope={'__name__':'pure_fixed_template_request'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-fixed-template-request>','exec'),scope)
request=scope['template_request'];decode=scope['decode_reply']
for v in p['vectors']:
 pid,getter,setter,before,after=request(v['args']);assert pid==123 and before==v['before'] and after==v['after'];assert getter==['get','sshd','action','nftables',v['args'][1]] and setter==['set','sshd','action','nftables',v['args'][1],v['after']]
base=p['vectors'][0]['args'];invalid=[]
for index,values in ((0,('1','0123','4194305')),(1,('port','actionban','actionstop','reload')),(2,('custom','nftables;id')),(3,('/bin/sh','nft;id')),(4,('inet','f2b;id','f2b table')),(5,('accept','chain$(id)')),(6,('ssh','22:22','22;id','022')),(7,('0','65536','22,22','2882,22','22'))):
 for value in values:
  args=base.copy();args[index]=value;invalid.append(args)
for args in invalid:
 try:request(args)
 except Exception:pass
 else:raise AssertionError('nonfixed template request accepted')
assert decode(pickle.dumps((0,'known literal')))=='known literal'
for raw in (b'cbuiltins\nset\n]R.',pickle.dumps((0,[]))+b'junk'):
 try:decode(raw)
 except Exception:pass
 else:raise AssertionError('executable or trailing template reply accepted')
print('PASS pure template grammar and exact source-derived renderer only; no socket, SET or subprocess')`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS pure template grammar") {
		t.Fatal(err, string(out))
	}
}

func TestIntrusionPortTemplateRetainsTheSamePrimitiveCodecAndNamedRootPeerGuards(t *testing.T) {
	cut := func(source, start, end string) string {
		t.Helper()
		a := strings.Index(source, start)
		if a < 0 {
			t.Fatal("guard prefix missing")
		}
		z := strings.Index(source[a:], end)
		if z < 0 {
			t.Fatal("guard suffix missing")
		}
		return source[a : a+z]
	}
	if cut(intrusionScalarMutationScript, "END = ", "def scalar_request(") != cut(intrusionPortTemplateMutationScript, "END = ", "def identifier(") {
		t.Fatal("safe primitive decoder drifted between fixed helpers")
	}
	if cut(intrusionScalarMutationScript, "    path = pathlib.Path(", `        if rpc(["version"])`) != cut(intrusionPortTemplateMutationScript, "    path = pathlib.Path(", `        if rpc(["version"])`) {
		t.Fatal("root peer/PID/socket/parent guards drifted between fixed helpers")
	}
}
