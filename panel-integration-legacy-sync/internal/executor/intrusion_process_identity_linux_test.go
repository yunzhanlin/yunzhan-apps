//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestIntrusionProcessLifetimeUsesCanonicalLosslessKernelTicks(t *testing.T) {
	for _, value := range []string{"1", "10000", "9007199254740993", "18446744073709551615"} {
		if !intrusionProcessTicksValid(value) {
			t.Fatal("canonical uint64 refused", value)
		}
		got, err := intrusionReadProcessStart(func(program string, args ...string) (string, error) {
			if program != "/usr/bin/fail2ban-client" || strings.Join(args, " ") != "get sshd process-start" {
				t.Fatal("nonfixed synthetic lifetime key", program, args)
			}
			return value + "\n", nil
		})
		if err != nil || got != value {
			t.Fatal("process ticks lost precision", got, err)
		}
	}
	for _, value := range []string{"", "0", "01", "+1", "-1", "1.0", "1e3", "１", "1;id", "18446744073709551616", strings.Repeat("1", 21), "1\n"} {
		if intrusionProcessTicksValid(value) {
			t.Fatal("noncanonical lifetime accepted", value)
		}
		if _, err := intrusionReadProcessStart(func(string, ...string) (string, error) { return value + "\n", nil }); err == nil {
			t.Fatal("noncanonical reader result accepted", value)
		}
	}
	if _, err := intrusionReadProcessStart(func(string, ...string) (string, error) { return "10000", nil }); err == nil {
		t.Fatal("unterminated lifetime accepted")
	}
}

func TestIntrusionProcessStatParserHandlesCommWithoutIOOrHostFallback(t *testing.T) {
	code := `import ast,sys
tree=ast.parse(sys.stdin.read());wanted={'canonical_process_ticks','parse_process_stat'};nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name in wanted];scope={'__name__':'pure_process_stat_parser'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-process-stat>','exec'),scope);parse=scope['parse_process_stat']
def line(pid=123,comm='fail2ban-server',ticks='9007199254740993',state='S'):
 return (str(pid)+' ('+comm+') '+' '.join([state]+['1']*18+[ticks]+['0']*30)+'\n').encode()
for comm in ('fail2ban-server','space in comm','brackets (and) spaces)','name) R 123 (nested)'):
 assert parse(line(comm=comm),123)=='9007199254740993'
assert parse(line(ticks='18446744073709551615'),123)=='18446744073709551615'
bad=[(line(pid=124),123),(line(),True),(line(),1),(line()[:-1],123),(line()+b'\n',123),(line()+b'\x00',123),(b'x'*4097,123),(b'123 (missing) S 1\n',123),(line(state='Z'),123),(line(state='T'),123),(line(ticks='0'),123),(line(ticks='01'),123),(line(ticks='+1'),123),(line(ticks='18446744073709551616'),123),(line().replace(b'123 (',b'0123 (',1),123)]
for raw,pid in bad:
 try:parse(raw,pid)
 except Exception:pass
 else:raise AssertionError('noncanonical or mismatching stat accepted')
print('PURE_PROCESS_LIFETIME_PARSER_OK')
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionProcessIdentityScript)
	raw, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(raw)) != "PURE_PROCESS_LIFETIME_PARSER_OK" {
		t.Fatal(err, string(raw))
	}
}

func TestIntrusionOriginalRejectsReusedPIDBeforeAnyScalarFileOrKernelWrite(t *testing.T) {
	s, lock, plan, raw, driver, answers := intrusionAdvanceFixture(t)
	defer lock.Close()
	before := intrusionUpgradeInventory(t, s.Config.SystemRoot)
	// The PID, boot, files, action text, scalar values and kernel handles all
	// remain identical. ONLY the independently observed kernel start differs.
	answers["/usr/bin/fail2ban-client get sshd process-start"] = "20000\n"
	ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, plan.ID)
	if err := s.intrusionJournalAdvance(ctx, lock, plan, raw, "committed", ""); err == nil {
		t.Fatal("new process inherited old original authority by PID number")
	}
	if len(driver.Scalars) != 0 || len(driver.Templates) != 0 || driver.Applies != 0 || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, s.Config.SystemRoot)) {
		t.Fatal("PID reuse changed original files or runtime")
	}
	_, retained, err := s.intrusionJournalPending()
	if err != nil || !bytes.Equal(retained, raw) {
		t.Fatal("PID refusal lost original recovery evidence", err)
	}
	for _, invalid := range []string{"", "0", "01", "18446744073709551616"} {
		changed := plan
		changed.ProcessStartBefore = invalid
		if _, err := intrusionJournalDerive(changed); err == nil {
			t.Fatal("unbound original lifetime accepted", invalid)
		}
	}
}

func TestIntrusionFixedActuatorsAndReceiptsBindOriginalProcessLifetime(t *testing.T) {
	change := intrusionScalarChange{Key: "maxretry", From: "5", To: "6"}
	for _, start := range []string{"", "0", "01", "1;id", "18446744073709551616"} {
		if _, err := intrusionScalarMutationArgs("123", start, "nftables", change); err == nil {
			t.Fatal("unbound scalar actuator accepted", start)
		}
	}
	value := intrusionScalarMutationReceipt{Format: 1, PID: "123", StartTicks: "20000", Field: "maxretry", Action: "-", From: "5", To: "6", Applied: true}
	raw, _ := json.Marshal(value)
	if _, err := intrusionScalarMutationDecode(raw, "123", "10000", "nftables", change); err == nil {
		t.Fatal("same-PID scalar receipt from another lifetime accepted")
	}
	plan := intrusionJournalFixture(t)
	after, err := intrusionPortRecipeTarget(plan)
	if err != nil {
		t.Fatal(err)
	}
	port := intrusionPortRecipeChange{Field: "actionstart", From: plan.ActionBefore.Values["actionstart"], To: after["actionstart"]}
	args, err := intrusionPortTemplateMutationArgs(plan, port)
	if err != nil || len(args) != 13 || args[12] != plan.ProcessStartBefore {
		t.Fatal("literal template actuator lacks original lifetime", err)
	}
	template := intrusionPortTemplateReceipt{Format: 1, PID: plan.ProcessBefore, StartTicks: "20000", Field: port.Field, Action: plan.BeforePolicy.Action, FromSHA256: core.Hash(port.From), ToSHA256: core.Hash(port.To), Applied: true}
	raw, _ = json.Marshal(template)
	if _, err := intrusionPortTemplateMutationDecode(raw, plan, port); err == nil {
		t.Fatal("same-PID template receipt from another lifetime accepted")
	}
}
