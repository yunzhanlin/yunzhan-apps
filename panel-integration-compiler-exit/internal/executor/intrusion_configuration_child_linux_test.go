//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestIntrusionConfigurationOwnedChildDiesWhenReadHelperIsCancelled(t *testing.T) {
	// Actual Linux process-lifetime probe using the SOURCE helper's guard.
	// Only a NEW test-owned interpreter sleeper is used; no Fail2ban service,
	// config, user process or installed app is started/stopped by this test.
	// The child proves PR_GET_PDEATHSIG survived its ordinary exec before its
	// PID is published. A pidfd pins only that child for observation/cleanup.
	code := `import ast,os,signal,subprocess,sys
tree=ast.parse(sys.stdin.read());nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name=='child_lifetime_guard'];scope={'__name__':'owned_child_lifetime_probe'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<source-child-guard>','exec'),scope)
child_code="import ctypes,os,signal,time; value=ctypes.c_int(); result=ctypes.CDLL(None).prctl(2,ctypes.byref(value),0,0,0); assert result==0 and value.value==signal.SIGKILL; print(os.getpid(),flush=True); time.sleep(30)"
with subprocess.Popen(['/usr/bin/python3','-I','-B','-c',child_code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,preexec_fn=scope['child_lifetime_guard'](),close_fds=True)as child:
 line=child.stdout.readline().decode().strip();assert line==str(child.pid);print(line,flush=True);child.wait(timeout=10)
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionConfigurationDumpScript)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill() // Only this test's own direct process handle.
			cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal("owned child did not confirm post-exec parent-death binding", err)
	}
	value := strings.TrimSuffix(line, "\n")
	pid, err := strconv.Atoi(value)
	if err != nil || pid < 2 || pid > 1<<22 || strconv.Itoa(pid) != value {
		t.Fatal("invalid owned child identity")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal("could not pin newly confirmed owned child", err)
	}
	defer unix.Close(fd)
	defer unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) // Never an unpinned PID.
	if ctx.Err() != nil {
		t.Fatal("owned process probe exceeded its original request deadline")
	}
	before := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(before, 0); err != nil || n != 0 {
		t.Fatal("owned child was not still running before parent cancellation", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal("could not cancel own read-helper process", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("read helper was not actually killed")
	}
	ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(ready, 2000)
	if err != nil || n != 1 || ready[0].Revents&unix.POLLIN == 0 {
		t.Fatal("new read-only child remained running after its helper died", err)
	}
}
