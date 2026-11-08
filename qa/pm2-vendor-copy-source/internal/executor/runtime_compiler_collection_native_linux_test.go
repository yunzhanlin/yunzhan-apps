//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRuntimeCompilerNativeCollectionClosesNewSessionBackgroundAndCancellation(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_COLLECTION_NATIVE") != "1" {
		t.Skip("explicit private dedicated Root service / actual native child collection required")
	}
	nativeCompilerCollectionFixture(t, false)
}

// Shared native witnesses do not widen either production command plan or unit
// authority. Only the internal test calls the bounded runner with a probe.
func nativeCompilerCollectionFixture(t *testing.T, apacheBody bool) {
	authority := nativeRuntimeCompilerAuthority
	if apacheBody {
		authority = nativeApacheCompilerAuthority
	}
	nativeCompilerCollectionFixtureKind(t, authority)
}

func nativeCompilerCollectionFixtureKind(t *testing.T, authority nativeCompilerAuthority) {
	t.Helper()
	apacheBody := authority == nativeApacheCompilerAuthority
	run := func(ctx context.Context, work, log, program string, args ...string) error {
		if authority != nativeRuntimeCompilerAuthority {
			return runScopedNativeBuildCommand(ctx, wafBuildCommand{Program: program, Directory: work, Arguments: args, Label: "private native collection probe"}, log, work, authority)
		}
		return buildCommand(ctx, work, log, program, args...)
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("collection fixture must supply the actual confined Root supervisor", identity)
	}
	builder, err := user.Lookup("panel-build")
	if err != nil || builder.Uid == "0" {
		t.Fatal("actual unprivileged builder unavailable", err)
	}
	uid, err := strconv.Atoi(builder.Uid)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "/run/panel-runtime-collection24amv"
	probe := `import json,os,pathlib,subprocess,sys,time
work=pathlib.Path.cwd()
child=r'''import json,os,pathlib,sys,time
identity={}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
 if line.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:','NoNewPrivs:')):
  key,value=line.split(':',1);identity[key]=value.strip()
assert os.geteuid()!=0 and all(identity[k]=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapAmb')) and identity['NoNewPrivs']=='1'
pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'pgid':os.getpgid(0),'uid':os.geteuid(),'cgroup':pathlib.Path('/proc/self/cgroup').read_text(),'identity':identity}))
time.sleep(60)
'''
children=[]
for name,new_session in (('same-group',False),('new-session',True)):
 children.append(subprocess.Popen(['/usr/bin/python3','-c',child,str(work/(name+'.json'))],start_new_session=new_session,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True))
deadline=time.monotonic()+8
while True:
 try:
  witnesses=[json.loads((work/(name+'.json')).read_text()) for name in ('same-group','new-session')]
  break
 except (FileNotFoundError,json.JSONDecodeError):
  assert all(p.poll() is None for p in children) and time.monotonic()<deadline
  time.sleep(.01)
assert witnesses[0]['pgid']==os.getpgid(0) and witnesses[1]['pgid']==witnesses[1]['pid'] and witnesses[1]['pgid']!=os.getpgid(0)
(work/'parent-ready').write_text('actual two child witnesses complete')
if sys.argv[1]=='cancel': time.sleep(60)
`
	proofs := []map[string]any{}
	for iteration := 0; iteration < 16; iteration++ {
		for _, mode := range []string{"background-success", "cancel"} {
			work := filepath.Join(fixture, fmt.Sprintf("%02d-%s", iteration, mode))
			if err := os.Mkdir(work, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(work, uid, -1); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			result := make(chan error, 1)
			go func() {
				result <- run(ctx, work, filepath.Join(fixture, fmt.Sprintf("%02d-%s.log", iteration, mode)), "/usr/bin/python3", "-c", probe, mode)
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(work, "parent-ready")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					cancel()
					t.Fatal("actual native child witnesses not ready", <-result)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if mode == "cancel" {
				cancel()
			}
			err := <-result
			cancel()
			if err == nil || (mode == "background-success" && !strings.Contains(err.Error(), "后台子进程")) || (mode == "cancel" && !errors.Is(err, context.Canceled)) {
				t.Fatal("native background / cancellation boundary did not fail closed", mode, err)
			}
			privateLog, readErr := os.ReadFile(filepath.Join(fixture, fmt.Sprintf("%02d-%s.log", iteration, mode)))
			if readErr != nil || !strings.Contains(string(privateLog), "compiler-collection-v2 ") || !strings.Contains(string(privateLog), "compiler-wait pid=") {
				t.Fatal("actual private numeric collection witnesses missing", readErr)
			}
			witnesses := []map[string]any{}
			for _, name := range []string{"same-group", "new-session"} {
				data, readErr := os.ReadFile(filepath.Join(work, name+".json"))
				var witness struct {
					PID, PGID, UID int
					Cgroup         string
					Identity       map[string]string
				}
				if readErr != nil || json.Unmarshal(data, &witness) != nil || witness.PID < 2 || witness.UID != uid {
					t.Fatal("actual native child identity missing", readErr, string(data))
				}
				decode := decodeRuntimeCompilerCgroup
				if apacheBody {
					decode = decodeApacheBodyCompilerCgroup
				}
				if authority == nativeNginxWAFCompilerAuthority {
					decode = decodeNginxWAFCompilerCgroup
				}
				if authority == nativeAnalyticsHTMLCompilerAuthority {
					decode = decodeAnalyticsHTMLCompilerCgroup
				}
				if _, err := decode(witness.Cgroup); err != nil {
					t.Fatal("child escaped the dedicated own service", err)
				}
				for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
					if witness.Identity[key] != "0000000000000000" {
						t.Fatal("native child capability not cleared", key)
					}
				}
				if witness.Identity["NoNewPrivs"] != "1" || (name == "new-session" && witness.PGID != witness.PID) {
					t.Fatal("native session/capability witness changed", witness)
				}
				if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(witness.PID))); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("native child or zombie remained after collection", mode, name, witness.PID, err)
				}
				var native map[string]any
				if err := json.Unmarshal(data, &native); err != nil {
					t.Fatal(err)
				}
				witnesses = append(witnesses, native)
			}
			proofs = append(proofs, map[string]any{"iteration": iteration, "mode": mode, "actual_children": witnesses, "collected_and_reaped": true, "returned_nonempty_failure": true})
		}
	}
	exitedProofs := nativeCompilerExitedDescendantsFixture(t, fixture, uid, run)
	// Before a new command, an unknown pre-existing member is not assumed to
	// be ours to terminate. The fixture owns this child and cleans up only it.
	unknown := exec.Command("/usr/bin/sleep", "60")
	if err := unknown.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unknown.Process.Kill(); _ = unknown.Wait() }()
	path := filepath.Join(fixture, "must-not-create.log")
	if err := run(context.Background(), fixture, path, "/usr/bin/true"); err == nil || !strings.Contains(err.Error(), "已有其他进程") {
		t.Fatal("unknown pre-existing service member accepted", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused command mutated its log", err)
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(unknown.Process.Pid))); err != nil {
		t.Fatal("refused command terminated unknown pre-existing member", err)
	}
	if err := unknown.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// An exited direct child remains a zombie until its owner waits. Preflight
	// must refuse without creating the log or stealing that child's status.
	fd, err := unix.PidfdOpen(unknown.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(3 * time.Second)
	for {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 10)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 && poll[0].Revents&unix.POLLIN != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned child did not exit")
		}
	}
	if task, err := compilerPIDFDTask(fd); err != nil || task != unknown.Process.Pid {
		t.Fatal("exited child no longer retained before wait", task, err)
	}
	if err := run(context.Background(), fixture, path, "/usr/bin/true"); err == nil || !strings.Contains(err.Error(), "已有其他进程") {
		t.Fatal("pre-existing zombie accepted or reaped", err)
	}
	if task, err := compilerPIDFDTask(fd); err != nil || task != unknown.Process.Pid {
		t.Fatal("preflight stole unknown zombie status", task, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("zombie refusal mutated log", err)
	}
	_ = unknown.Wait()
	if task, err := compilerPIDFDTask(fd); err != nil || task != -1 {
		t.Fatal("waited stable reference lacked exact reaping witness", task, err)
	}
	proof, err := json.MarshalIndent(map[string]any{"passed": true, "actual_build_command_executed": true, "apache_body_collector": apacheBody, "collector_authority": int(authority), "modes": proofs, "already_exited_owned_descendants": exitedProofs, "new_session_children_collected_and_reaped": true, "unknown_preexisting_member_preserved": true, "unknown_preexisting_zombie_status_preserved": true, "stable_pidfd_reaped_task_witness": true, "repetitions_per_mode": 16, "supervisor_identity": identity, "scope": "Actual private native compiler cancellation, exited descendant and background-process collection only; no source compilation, app receipt, runtime installation, public API or UI acceptance."}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(fixture, "proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_COLLECTION_PROOF", uid)
}

// A child deliberately killed by a configure feature probe is already dead,
// not a still-running daemon. WNOWAIT lets the probe prove that distinction
// before it exits and this dedicated supervisor adopts/reaps the zombie.
// Cover nonzero and signalled probes too: the direct command, not an unrelated
// feature probe's expected result, owns the build's exit status.
func nativeCompilerExitedDescendantsFixture(t *testing.T, fixture string, uid int, run func(context.Context, string, string, string, ...string) error) []map[string]any {
	t.Helper()
	const probe = `import json,os,pathlib,signal,sys
mode=sys.argv[1]
pid=os.fork()
if pid==0:
 if mode=='signal-kill': os.kill(os.getpid(),signal.SIGKILL)
 os._exit(42 if mode=='exit-nonzero' else 0)
info=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOWAIT)
assert info.si_pid==pid
text=pathlib.Path('/proc/'+str(pid)+'/stat').read_text()
assert text.split(') ',1)[1].split()[0]=='Z'
pathlib.Path('exited-child.json').write_text(json.dumps({'pid':pid,'uid':os.geteuid(),'code':info.si_code,'status':info.si_status,'state':'Z','cgroup':pathlib.Path('/proc/'+str(pid)+'/cgroup').read_text()}))
os._exit(23 if mode=='direct-failure' else 0)
`
	proofs := []map[string]any{}
	for iteration := 0; iteration < 8; iteration++ {
		for _, mode := range []string{"exit-zero", "exit-nonzero", "signal-kill", "direct-failure"} {
			name := fmt.Sprintf("exited-%02d-%s", iteration, mode)
			t.Run(name, func(t *testing.T) {
				work := filepath.Join(fixture, name)
				if err := os.Mkdir(work, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(work, uid, -1); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				log := filepath.Join(fixture, name+".log")
				err := run(ctx, work, log, "/usr/bin/python3", "-c", probe, mode)
				if mode == "direct-failure" {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 23 || strings.Contains(err.Error(), "后台子进程") {
						t.Fatal("direct command failure was lost or mistaken for a live descendant", err)
					}
				} else if err != nil {
					t.Fatal("fully exited owned probe was mistaken for a live background process", mode, err)
				}
				data, err := os.ReadFile(filepath.Join(work, "exited-child.json"))
				var witness struct {
					PID, UID, Code, Status int
					State, Cgroup          string
				}
				if err != nil || json.Unmarshal(data, &witness) != nil || witness.PID < 2 || witness.UID != uid || witness.State != "Z" {
					t.Fatal("actual owned exited-child witness missing", err)
				}
				if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(witness.PID))); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("owned exited child was not fully reaped", witness.PID, err)
				}
				status := "wait_status=0 exit=0 signal=0"
				if mode == "exit-nonzero" {
					status = "wait_status=10752 exit=42 signal=0"
				} else if mode == "signal-kill" {
					status = "wait_status=9 exit=-1 signal=9"
				}
				privateLog, err := os.ReadFile(log)
				if err != nil || !strings.Contains(string(privateLog), "compiler-collection-v2 member_snapshots=0 reaped=1 sampled=1") || !strings.Contains(string(privateLog), fmt.Sprintf("compiler-wait pid=%d %s\n", witness.PID, status)) {
					t.Fatal("actual exited-only numeric witness changed", err, string(privateLog))
				}
				proofs = append(proofs, map[string]any{"iteration": iteration, "mode": mode, "pid": witness.PID, "fully_reaped": true, "direct_command_failure_preserved": mode == "direct-failure", "live_background_not_observed": true})
			})
		}
	}
	return proofs
}
