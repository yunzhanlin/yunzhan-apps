//go:build linux

package executor

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

//go:embed testdata/intrusion-effective-stock-arm64.json
var intrusionEffectiveARMRawFixture []byte

//go:embed testdata/intrusion-effective-stock-amd64.json
var intrusionEffectiveAMDRawFixture []byte

// Explicit model metadata, NOT a digest measured from the historical capture
// or an installed daemon. Keep the original capture bytes immutable on disk.
func intrusionDeclaredFilterMetadata(version string) intrusionFilterMetadata {
	return intrusionFilterMetadata{Format: 1, Version: version, SHA256: strings.Repeat("a", 64)}
}

func intrusionDeclaredFilterDump(raw []byte, version string) []byte {
	var value intrusionEffectiveDump
	if err := json.Unmarshal(raw, &value); err != nil {
		panic(err)
	}
	metadata := intrusionDeclaredFilterMetadata(version)
	value.FilterMetadata = &metadata
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}

var intrusionEffectiveARMFixture = intrusionDeclaredFilterDump(intrusionEffectiveARMRawFixture, "1.0.2")
var intrusionEffectiveAMDFixture = intrusionDeclaredFilterDump(intrusionEffectiveAMDRawFixture, "1.1.0")

func intrusionEffectiveRuntimeFixture(t *testing.T, arch string) intrusionRuntimeState {
	t.Helper()
	p := intrusionActionRecipePolicy()
	var recipe intrusionActionRecipe
	if json.Unmarshal([]byte(intrusionActionRecipeFixture(t, p)), &recipe) != nil {
		t.Fatal("recipe fixture")
	}
	unit := "sshd.service"
	version := "1.0.2"
	if arch == "amd64" {
		unit = "ssh.service"
		version = "1.1.0"
	}
	return intrusionRuntimeState{Policy: p, Recipe: recipe, Settings: map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}, JournalMatch: "_SYSTEMD_UNIT=" + unit + " + _COMM=sshd", FilterMetadata: intrusionDeclaredFilterMetadata(version)}
}

func TestIntrusionEffectiveConfigurationAcceptsBothActualStrictDumpsWithoutRunningStream(t *testing.T) {
	for arch, raw := range map[string][]byte{"arm64": intrusionEffectiveARMFixture, "amd64": intrusionEffectiveAMDFixture} {
		t.Run(arch, func(t *testing.T) {
			runtime := intrusionEffectiveRuntimeFixture(t, arch)
			before := bytes.Clone(raw)
			out, err := intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings)
			if err != nil || len(out.Identity) != 64 || len(out.Commands) != 23 || !bytes.Equal(raw, before) {
				t.Fatal("actual unchanged config refused or original repaired", err)
			}
		})
	}
}

func TestIntrusionEffectiveConfigurationNormalizesOnlyOwnedLimitsAndPortRecipes(t *testing.T) {
	runtime := intrusionEffectiveRuntimeFixture(t, "arm64")
	before, err := intrusionEffectiveConfigurationDecode(intrusionEffectiveARMFixture, runtime, runtime.Settings)
	if err != nil {
		t.Fatal(err)
	}
	var changed intrusionEffectiveDump
	json.Unmarshal(intrusionEffectiveARMFixture, &changed)
	for _, cmd := range changed.Commands {
		if len(cmd) < 4 || cmd[1] != "sshd" {
			continue
		}
		if cmd[2] == "maxretry" {
			cmd[3] = float64(6)
		}
		if cmd[2] == "findtime" {
			cmd[3] = "11m"
		}
		if cmd[2] == "bantime" {
			cmd[3] = "61m"
		}
		if cmd[2] == "action" {
			for _, value := range cmd[4].([]any) {
				pair := value.([]any)
				if pair[0] == "port" {
					pair[1] = "22,2882"
				}
				if pair[0] == "actionstart" || pair[0] == "actionflush" {
					pair[1] = strings.ReplaceAll(pair[1].(string), "'22'", "'22,2882'")
				}
			}
		}
	}
	runtime.Policy.Ports = []int{22, 2882}
	json.Unmarshal([]byte(intrusionActionRecipeFixture(t, runtime.Policy)), &runtime.Recipe)
	runtime.Settings = map[string]int{"max_retry": 6, "find_time_minutes": 11, "ban_time_minutes": 61}
	raw, _ := json.Marshal(changed)
	after, err := intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings)
	if err != nil || before.Identity != after.Identity {
		t.Fatal("owned change lost fixed identity", err)
	}
	for _, cmd := range changed.Commands {
		if len(cmd) == 4 && cmd[1] == "sshd" && cmd[2] == "maxmatches" {
			cmd[3] = float64(6)
		}
	}
	raw, _ = json.Marshal(changed)
	runtime.Policy.MaxMatches = 6
	after, err = intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings)
	if err != nil || before.Identity == after.Identity {
		t.Fatal("non-owned maxmatches silently discarded", err)
	}
}

func TestIntrusionEffectiveConfigurationRetainsFiltersOtherJailsAndGlobalState(t *testing.T) {
	runtime := intrusionEffectiveRuntimeFixture(t, "arm64")
	before, err := intrusionEffectiveConfigurationDecode(intrusionEffectiveARMFixture, runtime, runtime.Settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"filter", "global", "other-jail"} {
		t.Run(kind, func(t *testing.T) {
			var d intrusionEffectiveDump
			json.Unmarshal(intrusionEffectiveARMFixture, &d)
			switch kind {
			case "filter":
				for _, c := range d.Commands {
					if len(c) == 4 && c[1] == "sshd" && c[2] == "prefregex" {
						c[3] = "new-filter"
					}
				}
			case "global":
				d.Commands[0][2] = "/run/custom-log"
			case "other-jail":
				d.Commands = append(d.Commands, []any{"add", "other_jail", "systemd"})
			}
			raw, _ := json.Marshal(d)
			after, err := intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings)
			if err != nil || before.Identity == after.Identity {
				t.Fatal("non-owned config ignored", err)
			}
		})
	}
}

func TestIntrusionEffectiveConfigurationRejectsUnknownOrIncompleteReloadAuthority(t *testing.T) {
	runtime := intrusionEffectiveRuntimeFixture(t, "arm64")
	for name, change := range map[string]func(*intrusionEffectiveDump){
		"backend-change": func(d *intrusionEffectiveDump) {
			for _, c := range d.Commands {
				if c[0] == "add" && c[1] == "sshd" {
					c[2] = "polling"
				}
			}
		},
		"extra-action": func(d *intrusionEffectiveDump) {
			d.Commands = append(d.Commands[:len(d.Commands)-1], []any{"set", "sshd", "addaction", "mail"}, []any{"start", "sshd"})
		},
		"duplicate-field": func(d *intrusionEffectiveDump) {
			d.Commands = append(d.Commands[:len(d.Commands)-1], []any{"set", "sshd", "maxretry", float64(5)}, []any{"start", "sshd"})
		},
		"missing-action": func(d *intrusionEffectiveDump) {
			for i, c := range d.Commands {
				if len(c) > 2 && c[2] == "action" {
					d.Commands = append(d.Commands[:i], d.Commands[i+1:]...)
					break
				}
			}
		},
		"wrong-limit": func(d *intrusionEffectiveDump) {
			for _, c := range d.Commands {
				if len(c) == 4 && c[2] == "maxretry" {
					c[3] = float64(6)
				}
			}
		},
		"extra-script": func(d *intrusionEffectiveDump) {
			for _, c := range d.Commands {
				if len(c) == 5 && c[2] == "action" {
					c[4] = append(c[4].([]any), []any{"actionreload", "echo private-backend-sentinel"})
				}
			}
		},
		"changed-action": func(d *intrusionEffectiveDump) {
			for _, c := range d.Commands {
				if len(c) == 5 && c[2] == "action" {
					for _, p := range c[4].([]any) {
						pair := p.([]any)
						if pair[0] == "actionstop" {
							pair[1] = "echo private-backend-sentinel"
						}
					}
				}
			}
		},
		"unban-command": func(d *intrusionEffectiveDump) { d.Commands = append(d.Commands, []any{"unban", "--all"}) },
		"nested-object": func(d *intrusionEffectiveDump) { d.Commands[0][2] = map[string]any{"command": "stop"} },
		"null-value":    func(d *intrusionEffectiveDump) { d.Commands[0][2] = nil },
		"out-of-order":  func(d *intrusionEffectiveDump) { d.Commands[7], d.Commands[8] = d.Commands[8], d.Commands[7] },
	} {
		t.Run(name, func(t *testing.T) {
			var d intrusionEffectiveDump
			json.Unmarshal(intrusionEffectiveARMFixture, &d)
			change(&d)
			raw, _ := json.Marshal(d)
			if _, err := intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings); err == nil || strings.Contains(err.Error(), "private-backend-sentinel") {
				t.Fatal("unsafe dump accepted or leaked", err)
			}
		})
	}
	for _, raw := range []string{string(intrusionEffectiveARMFixture) + `{}`, strings.Replace(string(intrusionEffectiveARMFixture), `"format": 1`, `"format": 1,"FORMAT": 1`, 1), `{"format":1,"commands":[]}`} {
		if _, err := intrusionEffectiveConfigurationDecode([]byte(raw), runtime, runtime.Settings); err == nil {
			t.Fatal("nonclosed config accepted")
		}
	}
}

func TestIntrusionEffectiveConfigurationPrivateHelperInvokesOnlyFixedTestDump(t *testing.T) {
	runtime := intrusionEffectiveRuntimeFixture(t, "arm64")
	calls := 0
	s := &Service{Config: Config{Run: func(ctx context.Context, p string, args ...string) (string, error) {
		calls++
		if p != "/usr/bin/python3" || len(args) != 4 || args[0] != "-I" || args[1] != "-B" || args[2] != "-c" || args[3] != intrusionConfigurationDumpScript {
			t.Fatal("nonfixed external command")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing fixed deadline")
		}
		return string(intrusionEffectiveARMFixture), nil
	}}}
	if _, err := s.readIntrusionEffectiveConfiguration(context.Background(), runtime, runtime.Settings); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
}

func TestIntrusionEffectiveDumpLiteralParserNeverExecutesDeclarations(t *testing.T) {
	// Load ONLY imports and the pure parser; main/subprocess are never called.
	code := `import ast,sys
source=sys.stdin.read();tree=ast.parse(source);nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name=='parse_dump'];scope={'__name__':'pure_configuration_parser'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-dump-parser>','exec'),scope);parse=scope['parse_dump'];suffix=b'\nOK: configuration test is successful\n'
assert parse(b"['set','sshd','maxretry',5]"+suffix)=={'format':1,'commands':[['set','sshd','maxretry',5]]}
bad=[b"__import__('os').system('exit 77')"+suffix,b"['set','sshd',{'script':'stop'}]"+suffix,b"['set','sshd',None]"+suffix,b"['set','sshd',1.5]"+suffix,b"['set','sshd',True]\n",b"['set','sshd','maxretry',5]\nOK: partial\n",b"["*14+b"0"+b"]"*14+suffix,b"['set','sshd',9007199254740992]"+suffix]
for raw in bad:
 try:parse(raw)
 except Exception:pass
 else:raise AssertionError('nonliteral or incomplete test accepted')
print('PASS pure closed dump parser; no child, socket, stream or service operation')`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionConfigurationDumpScript)
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), "PASS pure closed dump parser") {
		t.Fatal(err, string(raw))
	}
}
