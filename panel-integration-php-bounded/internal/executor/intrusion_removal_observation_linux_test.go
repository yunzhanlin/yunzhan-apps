//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestIntrusionRemovalObservationUsesOnlyNewFixedTestCopyAndKeepsUnknownOutcomes(t *testing.T) {
	for _, kind := range []string{"ready", "backend-error", "truncated", "invalid-baseline", "source-changed", "copy-replaced", "cancelled-child", "unbound-lock", "extra-output"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, before, jail := intrusionRemovalCopyFixture(t)
			current, dump, identity := intrusionRemovalCandidateFixture(t, "arm64")
			raw, _ := json.Marshal(dump)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, stage := 0, ""
			s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok || program != "/usr/bin/python3" || len(args) != 6 || !slices.Equal(args[:5], []string{"-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate"}) {
					t.Fatal("nonfixed, unbounded, mutating or implicit fallback command")
				}
				stage = args[5]
				if filepath.Dir(stage) != filepath.Join(s.Config.SecurityDir, intrusionRemovalCacheName) || !intrusionRemovalCopyName.MatchString(filepath.Base(stage)) {
					t.Fatal("caller selected a candidate root")
				}
				if _, err := os.Lstat(filepath.Join(stage, "jail.d/panel-intrusion.local")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("fixed child received installed or unfiltered configuration", err)
				}
				switch kind {
				case "backend-error":
					return "private-backend-sentinel", errors.New("private-backend-sentinel")
				case "truncated":
					return string(raw[:len(raw)/2]), nil
				case "invalid-baseline":
					intrusionRemovalCandidateSet(t, &dump, "prefregex", "^private-backend-sentinel$")
					raw, _ = json.Marshal(dump)
				case "source-changed":
					if err := os.WriteFile(s.systemPath("/etc/fail2ban/jail.conf"), []byte("external source change\n"), 0644); err != nil {
						t.Fatal(err)
					}
				case "copy-replaced":
					if err := atomicWrite(filepath.Join(stage, "jail.conf"), []byte("[DEFAULT]\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "cancelled-child":
					cancel()
				case "unbound-lock":
					lock.Close()
				case "extra-output":
					return string(raw) + "{}", nil
				}
				return string(raw), nil
			}
			got, err := s.readIntrusionRemovalCandidate(ctx, lock, before, jail, current, identity)
			if calls != 1 || stage == "" {
				t.Fatal("read-only child skipped or implicitly retried", calls)
			}
			if kind == "ready" {
				if err != nil || got.EffectiveIdentity != identity || !reflect.DeepEqual(got.Settings, current.Settings) || !slices.Equal(got.Ports, current.Policy.Ports) {
					t.Fatal(got, err)
				}
			} else if err == nil || !reflect.DeepEqual(got, intrusionRemovalCandidate{}) || strings.Contains(err.Error(), "private-backend-sentinel") {
				t.Fatal("unknown result became candidate or leaked child data", got, err)
			}
			_, stageErr := os.Lstat(stage)
			retained := kind == "copy-replaced" || kind == "cancelled-child" || kind == "unbound-lock"
			if retained && stageErr != nil || !retained && !errors.Is(stageErr, os.ErrNotExist) {
				t.Fatal("unsafe candidate erased or known new copy left behind", retained, stageErr)
			}
			after, treeErr := s.readIntrusionConfigurationTree(context.Background())
			if kind == "source-changed" {
				data, readErr := os.ReadFile(s.systemPath("/etc/fail2ban/jail.conf"))
				if readErr != nil || string(data) != "external source change\n" {
					t.Fatal("external source change was overwritten", readErr)
				}
			} else if treeErr != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("candidate observation changed installed source", treeErr)
			}
		})
	}
}

func TestIntrusionRemovalCandidatePythonPathGuardIsClosedPurePermissionModel(t *testing.T) {
	// Unit grammar/permission model ONLY: no path is read and no client/child
	// is launched. Native acceptance must separately exercise the real -c dump.
	code := `import ast,pathlib,stat,sys,types
tree=ast.parse(sys.stdin.read());nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name=='candidate_identity'];scope={'__name__':'pure_candidate_path_model'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-candidate-guard>','exec'),scope)
overrides={}
class ModelPath(pathlib.PurePosixPath):
 def lstat(self):
  values={'st_dev':1,'st_ino':abs(hash(str(self)))+1,'st_mode':stat.S_IFDIR|0o700,'st_uid':0,'st_gid':0};values.update(overrides.get(str(self),{}));return types.SimpleNamespace(**values)
scope['pathlib']=types.SimpleNamespace(Path=ModelPath);guard=scope['candidate_identity'];good='/owned/security/.intrusion-removal-candidates/candidate-'+'a'*32
assert len(guard(good))==5
bad=['relative', '/etc/fail2ban', good+'/', '/'+good, good.replace('candidate-','other-'),good.replace('a'*32,'A'*32),good.replace('/security/','/security/../security/'),good.replace('/security/','/security/./'),good+'x']
for raw in bad:
 try:guard(raw)
 except Exception:pass
 else:raise AssertionError('unqualified path accepted')
for target,change in[(good,{'st_mode':stat.S_IFDIR|0o500}),(str(ModelPath(good).parent),{'st_mode':stat.S_IFDIR|0o755}),('/owned',{'st_uid':1}),('/owned',{'st_mode':stat.S_IFDIR|0o777}),(good,{'st_mode':stat.S_IFLNK|0o700}),('/owned',{'st_mode':stat.S_IFDIR|0o2755})]:
 overrides={target:change}
 try:guard(good)
 except Exception:pass
 else:raise AssertionError('untrusted principal/mode/link accepted')
overrides={};assert len(guard(good))==5
print('PASS pure candidate path/permission model; no filesystem or child operation')`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionConfigurationDumpScript)
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), "PASS pure candidate path/permission model") {
		t.Fatal(err, string(raw))
	}
}

func TestIntrusionRemovalCandidateIncludeGrammarCannotReadBackOriginalOwnedJail(t *testing.T) {
	// Pure path grammar/source-order check, NOT an upstream-parser or native
	// filesystem acceptance. That requires the owned actual -c fixture.
	code := `import ast,sys
tree=ast.parse(sys.stdin.read());nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name=='candidate_include_targets'];scope={'__name__':'pure_candidate_includes'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-include-guard>','exec'),scope);targets=scope['candidate_include_targets']
assert targets('jail.conf','paths-common.conf')==['paths-common.conf','paths-common.local']
assert targets('filter.d/sshd.conf','common.conf\nextra.local')==['filter.d/common.conf','filter.d/common.local','filter.d/extra.local']
assert targets('filter.d/sshd.conf','../paths-common.conf')==['paths-common.conf','paths-common.local']
assert targets('jail.conf','')==[]
bad=[('jail.conf','/etc/fail2ban/jail.d/panel-intrusion.local'),('filter.d/sshd.conf','../../outside.conf'),('jail.conf','%(external)s'),('jail.conf','%%name.conf'),('jail.conf','https://example.invalid/config'),('jail.conf','common.conf\x00'),('jail.conf','common.conf\r'),('jail.conf',r'..\outside.conf'),('../source.conf','safe.conf'),('/etc/jail.conf','safe.conf'),('jail.conf','../outside.conf'),('jail.conf','.'),('jail.conf','x'*16385),('jail.conf','a/'*8+'x.conf')]
for resource,value in bad:
 try:targets(resource,value)
 except Exception:pass
 else:raise AssertionError('unqualified include became a private candidate')
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');checks=[n.lineno for n in ast.walk(main)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='candidate_includes'];children=[n.lineno for n in ast.walk(main)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Popen'];assert len(checks)==len(children)==1 and checks[0]<children[0]
print('PASS pure include grammar and pre-client guard order; no filesystem/client operation')`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionConfigurationDumpScript)
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), "PASS pure include grammar and pre-client guard order") {
		t.Fatal(err, string(raw))
	}
}
