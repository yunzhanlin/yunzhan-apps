//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func intrusionBatchFixture(t *testing.T) []byte {
	t.Helper()
	result := intrusionReadOnlyBatch{Format: 1, PID: "123", Version: "1.0.2"}
	for _, args := range [][]string{{"status", "sshd"}, {"get", "sshd", "actions"}, {"get", "sshd", "journalmatch"}, {"get", "sshd", "maxretry"}, {"get", "sshd", "findtime"}, {"get", "sshd", "bantime"}, {"get", "sshd", "banip"}, {"get", "sshd", "maxmatches"}} {
		result.Observations = append(result.Observations, intrusionReadOnlyBatchObservation{Args: args, OK: true, Value: "observed\n"})
	}
	metadata, err := json.Marshal(intrusionDeclaredFilterMetadata("1.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	result.Observations = append(result.Observations, intrusionReadOnlyBatchObservation{Args: []string{"get", "sshd", "filter-metadata"}, OK: true, Value: string(metadata)})
	result.Observations = append(result.Observations, intrusionReadOnlyBatchObservation{Args: []string{"get", "sshd", "process-start"}, OK: true, Value: "10000\n"})
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIntrusionBatchDecoderIsClosedBoundedAndBindsActualProcess(t *testing.T) {
	raw := intrusionBatchFixture(t)
	if values, err := intrusionDecodeReadOnlyBatch(raw, "123"); err != nil || len(values) != 10 {
		t.Fatal(values, err)
	}
	for name, change := range map[string]func(*intrusionReadOnlyBatch){
		"pid":           func(v *intrusionReadOnlyBatch) { v.PID = "124" },
		"version":       func(v *intrusionReadOnlyBatch) { v.Version = "2.0.0" },
		"format":        func(v *intrusionReadOnlyBatch) { v.Format = 0 },
		"missing-range": func(v *intrusionReadOnlyBatch) { v.Observations = v.Observations[:6] },
		"duplicate":     func(v *intrusionReadOnlyBatch) { v.Observations = append(v.Observations, v.Observations[0]) },
		"write-command": func(v *intrusionReadOnlyBatch) {
			v.Observations[0].Args = []string{"set", "sshd", "banip", "127.0.0.2"}
		},
		"other-jail": func(v *intrusionReadOnlyBatch) { v.Observations[0].Args = []string{"status", "other"} },
		"error-leak": func(v *intrusionReadOnlyBatch) {
			v.Observations[0].OK = false
			v.Observations[0].Value = "private-backend-sentinel"
		},
		"capacity": func(v *intrusionReadOnlyBatch) { v.Observations[0].Value = strings.Repeat("x", (24<<10)+1) },
	} {
		t.Run(name, func(t *testing.T) {
			var v intrusionReadOnlyBatch
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			change(&v)
			bad, _ := json.Marshal(v)
			if _, err := intrusionDecodeReadOnlyBatch(bad, "123"); err == nil || strings.Contains(err.Error(), "private-backend-sentinel") {
				t.Fatal("invalid batch accepted or leaked", err)
			}
		})
	}
	for name, bad := range map[string][]byte{"unknown": []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"command":"reboot"`, 1)), "duplicate-root": []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"FORMAT":1`, 1)), "trailing": append(append([]byte{}, raw...), []byte(`{}`)...), "partial": raw[:len(raw)/2]} {
		t.Run(name, func(t *testing.T) {
			if _, err := intrusionDecodeReadOnlyBatch(bad, "123"); err == nil {
				t.Fatal("nonclosed response accepted")
			}
		})
	}
}

func TestIntrusionBatchSessionSamplesAfterKernelAndDoesNotImplicitlyRetry(t *testing.T) {
	for _, kind := range []string{"stable", "static-drift", "transport-failure"} {
		t.Run(kind, func(t *testing.T) {
			batches := 0
			kernelRead := false
			s := &Service{Config: Config{SystemRoot: "/", Run: func(_ context.Context, program string, args ...string) (string, error) {
				if program == "/usr/bin/systemctl" && strings.Join(args, " ") == "show fail2ban.service --property=MainPID,ActiveState" {
					return "MainPID=123\nActiveState=active\n", nil
				}
				if program == "/usr/sbin/nft" {
					kernelRead = true
					return `{"nftables":[]}`, nil
				}
				if program != "/usr/bin/python3" || len(args) != 5 || args[0] != "-I" || args[1] != "-B" || args[2] != "-c" || args[3] != intrusionReadOnlyBatchScript || args[4] != "123" {
					t.Fatal("unexpected or nonfixed batch invocation", program)
				}
				batches++
				if batches == 2 && !kernelRead {
					t.Fatal("second phase prefetched before actual kernel read")
				}
				if kind == "transport-failure" {
					return "private-backend-sentinel", errors.New("private error")
				}
				raw := intrusionBatchFixture(t)
				if kind == "static-drift" && batches == 2 {
					var v intrusionReadOnlyBatch
					json.Unmarshal(raw, &v)
					v.Observations[3].Value = "changed\n"
					raw, _ = json.Marshal(v)
				}
				return string(raw), nil
			}}}
			read := s.intrusionReadOnlySession(context.Background())
			_, err := read("/usr/bin/fail2ban-client", "status", "sshd")
			if kind == "transport-failure" {
				if err == nil || strings.Contains(err.Error(), "private-backend-sentinel") {
					t.Fatal(err)
				}
				read("/usr/bin/fail2ban-client", "get", "sshd", "banip")
				if batches != 1 {
					t.Fatal("failed batch implicitly retried")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = read("/usr/bin/fail2ban-client", "get", "sshd", "banip"); err != nil {
				t.Fatal(err)
			}
			if batches != 1 {
				t.Fatal("first phase not shared")
			}
			read("/usr/sbin/nft", "-j", "list", "tables")
			_, err = read("/usr/bin/fail2ban-client", "get", "sshd", "banip")
			if batches != 2 || (kind == "static-drift") != (err != nil) {
				t.Fatal("phase two/static drift contract", batches, err)
			}
			if kind == "stable" {
				if _, err = read("/usr/bin/fail2ban-client", "get", "sshd", "banip"); err == nil || batches != 2 {
					t.Fatal("third phase executed")
				}
			}
		})
	}
}

func TestIntrusionBatchSessionRejectsMutatorsBeforeAnyCommand(t *testing.T) {
	s := &Service{Config: Config{SystemRoot: "/", Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("denied request executed an external command")
		return "", nil
	}}}
	read := s.intrusionReadOnlySession(context.Background())
	for _, args := range [][]string{{"reload", "sshd"}, {"stop", "sshd"}, {"get", "other", "actions"}, {"get", "sshd", "action", "nftables", "__class__"}, {"get", "sshd", "action", "custom", "actionstart"}, {"set", "sshd", "banip", "127.0.0.2"}} {
		if _, err := read("/usr/bin/fail2ban-client", args...); err == nil {
			t.Fatal("unknown read or mutator accepted", args)
		}
	}
}

func TestIntrusionBatchWirePrimitiveCodecRejectsCodeGraphsAndWriteRequests(t *testing.T) {
	// Only import/constants and four pure codec/whitelist functions are loaded;
	// main(), filesystem/socket connection code and its __main__ block are NOT
	// executed. This test cannot connect to or mutate an installed service.
	code := `import ast,io,pickle,pickletools,sys
source=sys.stdin.read();tree=ast.parse(source);wanted={'decode_reply','allowed','action_names','ban_addresses'};nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign)) or isinstance(n,ast.FunctionDef)and n.name in wanted or isinstance(n,ast.ClassDef)and n.name=='Primitives'];assert {n.name for n in nodes if isinstance(n,ast.FunctionDef)}==wanted;scope={'__name__':'isolated_codec_fixture'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<only-pure-readonly-codec>','exec'),scope)
decode=scope['decode_reply'];allowed=scope['allowed'];bans=scope['ban_addresses']
assert decode(pickle.dumps((0,['nftables']),protocol=5))==['nftables']
assert decode(pickle.dumps((0,[]),protocol=2))==[]
bad=[b'cbuiltins\nset\n]R.',pickle.dumps((0,[]))+b'junk',b'\x80\x02]r\x01\x20\x00\x00.',pickle.dumps((0,[0]*1025))]
cyclic=[];cyclic.append(cyclic);bad.append(pickle.dumps((0,cyclic)))
deep=0
for i in range(14):deep=[deep]
bad.append(pickle.dumps((0,deep)))
for raw in bad:
 try:decode(raw)
 except Exception:pass
 else:raise AssertionError('nonprimitive, recursive, deep, oversized or memo payload accepted')
assert allowed(['get','sshd','actions'])and allowed(['get','sshd','action','nftables','port'])
for args in (['set','sshd','banip','127.0.0.2'],['reload','sshd'],['get','other','actions'],['get','sshd','action','nftables','__class__']):assert not allowed(args)
assert bans([])=='\n'
assert bans(['127.0.0.2 \t2026-10-20 00:00:00 + 600 = 2026-10-20 00:10:00','2001:db8::2 \t2026-10-20 00:00:00 + 600 = 2026-10-20 00:10:00'])=='127.0.0.2 2001:db8::2\n'
for rows in (['127.0.0.2'],['127.0.0.2 \tx','127.0.0.2 \tx'],['::ffff:127.0.0.2 \tx'],['fe80::1%eth0 \tx']):
 try:bans(rows)
 except Exception:pass
 else:raise AssertionError('unknown ban shape accepted')
print('PURE_READONLY_PROTOCOL_CODEC_OK')
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionReadOnlyBatchScript)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "PURE_READONLY_PROTOCOL_CODEC_OK" {
		t.Fatal("pure protocol codec failed", err, string(out))
	}
}

func TestIntrusionObservationCancellationIsNotReportedAsBanDrift(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		s, _, _ := intrusionRuntimeFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if runtime {
			_, err := s.readIntrusionMutationRuntime(ctx)
			if err == nil || !strings.Contains(err.Error(), "取消") {
				t.Fatal(err)
			}
		} else {
			_, err := s.inspectIntrusion(ctx)
			if err == nil || !strings.Contains(err.Error(), "取消") || strings.Contains(err.Error(), "封禁列表") {
				t.Fatal(err)
			}
		}
	}
}
