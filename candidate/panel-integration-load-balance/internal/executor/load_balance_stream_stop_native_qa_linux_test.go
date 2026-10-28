//go:build linux

package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

// Real PID1/cgroup/pidfd component evidence, never an application-control
// receipt. The production unit, NSS, Core requests and generations are untouched.
func TestLoadBalanceStreamStopNativeOriginalCleanAndChildOOMAreDistinct(t *testing.T) {
	anchor := os.Getenv("PANEL_LBSTREAM_STOP_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit isolated Root native PID1 stop component required")
	}
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Geteuid() != 0 || os.Getegid() != 0 ||
		!regexp.MustCompile(`^/var/lib/panel-executor/qa-l4-stop24-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) ||
		threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("closed distinct original Root native stop fixture required")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(pid1) != "systemd\n" {
		t.Fatal("actual native PID1 systemd required", err)
	}
	command := func(t *testing.T, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		raw, err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("own native unit command %v: %v: %s", args, err, raw)
		}
		return raw
	}
	for _, mode := range []string{"clean", "child-oom"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			unit := "panel-owned-l4-stop-" + core.ID() + "-" + mode + ".service"
			path := "/run/systemd/system/" + unit
			// Both cases exit the master normally. Only the child allocates;
			// its local 48MiB cgroup limit bounds the intentional OOM witness.
			worker := `import os,signal,time,sys
root=sys.argv[1]
child=os.fork()
if child==0:
 signal.signal(signal.SIGQUIT,lambda *_:sys.exit(0))
 def allocate(*_):
  x=bytearray(128<<20)
  time.sleep(30)
 signal.signal(signal.SIGUSR1,allocate)
 with open(root+'/child-ready','x')as f:f.write(str(os.getpid()))
 while True:time.sleep(.05)
def clean(*_):
 os.kill(child,signal.SIGQUIT)
 os.waitpid(child,0)
 sys.exit(0)
signal.signal(signal.SIGQUIT,clean)
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
signal.signal(signal.SIGUSR1,lambda *_:os.kill(child,signal.SIGUSR1))
with open(root+'/master-ready','x')as f:f.write(str(os.getpid()))
while True:time.sleep(.05)
`
			if err := os.WriteFile(filepath.Join(base, "worker.py"), []byte(worker), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				t.Fatal("never replace another unit", err)
			}
			text := fmt.Sprintf("[Unit]\nDescription=Owned native stop evidence component\n[Service]\nType=exec\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 -I -B %s/worker.py %s\nOOMPolicy=stop\nMemoryMax=48M\nTasksMax=8\nRuntimeMaxSec=60\n", base, base)
			_, writeErr := f.WriteString(text)
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(writeErr, closeErr)
			}
			t.Cleanup(func() {
				command(t, "stop", unit)
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
				command(t, "daemon-reload")
			})
			command(t, "daemon-reload")
			command(t, "start", unit)
			deadline := time.Now().Add(15 * time.Second)
			var pids []int
			for {
				a, e1 := os.ReadFile(filepath.Join(base, "master-ready"))
				b, e2 := os.ReadFile(filepath.Join(base, "child-ready"))
				master, e3 := strconv.Atoi(string(a))
				child, e4 := strconv.Atoi(string(b))
				if e1 == nil && e2 == nil && e3 == nil && e4 == nil && master > 1 && child > 1 && master != child {
					pids = []int{master, child}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("own native worker readiness not observed")
				}
				time.Sleep(50 * time.Millisecond)
			}
			invocation := strings.TrimSpace(string(command(t, "show", unit, "--property=InvocationID", "--value")))
			if !core.ValidID(invocation) || invocation == strings.Repeat("0", 32) {
				t.Fatal("missing original manager invocation")
			}
			group := "/sys/fs/cgroup/system.slice/" + unit
			held, err := os.Open(group)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			before, err := held.Stat()
			if err != nil {
				t.Fatal(err)
			}
			fds := []int{}
			for _, pid := range pids {
				fd, err := unix.PidfdOpen(pid, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				fds = append(fds, fd)
			}
			signal := unix.SIGQUIT
			if mode == "child-oom" {
				signal = unix.SIGUSR1
			}
			if err := unix.PidfdSendSignal(fds[0], signal, nil, 0); err != nil {
				t.Fatal(err)
			}
			for {
				exited := true
				for _, fd := range fds {
					poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					n, err := unix.Poll(poll, 0)
					exited = exited && err == nil && n == 1 && poll[0].Revents&unix.POLLIN != 0
				}
				if exited {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("both original held pidfds must observe exit")
				}
				time.Sleep(50 * time.Millisecond)
			}
			// PID1 reaps asynchronously after pidfd readiness. Wait for its
			// retained exit and pruning; never synthesize a final counter read.
			var raw []byte
			for {
				raw = command(t, "show", unit, "--property="+streamStoppedPrunedExitProperties)
				_, e := os.Lstat(group)
				if os.IsNotExist(e) && strings.Contains(string(raw), "MainPID=0\n") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("original manager exit and cgroup pruning not observed")
				}
				time.Sleep(50 * time.Millisecond)
			}
			after, err := held.Stat()
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("original held cgroup inode changed", err)
			}
			// Keep the actual own-unit Id. These component bytes must never
			// be relabelled as evidence for the production application unit.
			want := map[string]string{"Id": unit, "LoadState": "loaded", "ActiveState": "active", "SubState": "exited", "MainPID": "0", "ControlPID": "0", "InvocationID": invocation, "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0", "RemainAfterExit": "yes", "OOMPolicy": "stop", "ControlGroup": ""}
			accepted := streamExactManagerProperties(raw, want)
			if accepted != (mode == "clean") || !strings.Contains(string(raw), "ExecMainCode=1\n") || !strings.Contains(string(raw), "ExecMainStatus=0\n") ||
				mode == "child-oom" && !strings.Contains(string(raw), "Result=oom-kill\n") {
				t.Fatalf("clean master must not conceal child OOM: accepted=%t, actual=%s", accepted, raw)
			}
			t.Logf("actual own-unit component mode=%s accepted=%t original_pidfds_exited=true cgroup_pruned=true properties=%s", mode, accepted, raw)
		})
	}
}
