//go:build linux

package diskjob

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHostNativeProcessChild(t *testing.T) {
	if os.Getenv("PANEL_DISK_PROCESS_TEST_CHILD") != "fixed-source-only" {
		return
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		os.Exit(2)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestHostNativeProcessPIDFDOriginalIdentityAndReadOnlyExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root original process not verified; not commercial acceptance")
	}
	host, err := ReadHost()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := processSHA("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	input, feed, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	defer input.Close()
	cmd := exec.Command(exe, "-test.run=^TestHostNativeProcessChild$")
	cmd.Env = append(os.Environ(), "PANEL_DISK_PROCESS_TEST_CHILD=fixed-source-only")
	cmd.Stdin = input
	ready, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		feed.Close()
		if !reaped {
			cmd.Wait()
		}
	})
	buf := make([]byte, 6)
	if _, err := io.ReadFull(ready, buf); err != nil || string(buf) != "ready\n" {
		t.Fatal("native child never became ready", err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	raw, err := fixedKernelRead("/proc/"+pid+"/stat", 8192, unix.PROC_SUPER_MAGIC)
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processTicks(raw, pid)
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := fixedKernelRead("/proc/"+pid+"/cgroup", 4096, unix.PROC_SUPER_MAGIC)
	if err != nil || !strings.HasPrefix(string(cgroup), "0::") {
		t.Fatal(err)
	}
	s := Started{PID: pid, StartTicks: ticks, ExecutorSHA: sha, Policy: Policy{Host: host, Cgroup: strings.TrimSpace(strings.TrimPrefix(string(cgroup), "0::"))}}
	if got := observeProcess(s); got != "alive" {
		t.Fatal("original live pidfd identity unavailable", got)
	}
	wrong := s
	wrong.StartTicks = "1"
	if got := observeProcess(wrong); got != "gone" {
		t.Fatal("reused PID adopted as original", got)
	}
	wrong = s
	wrong.ExecutorSHA = strings.Repeat("1", 64)
	if got := observeProcess(wrong); got != "unknown" {
		t.Fatal("unmatched executable treated as completed/matched", got)
	}
	wrong = s
	wrong.Policy.Cgroup = "/not-original"
	if got := observeProcess(wrong); got != "unknown" {
		t.Fatal("unmatched cgroup accepted", got)
	}
	if got := observeProcess(s); got != "alive" {
		t.Fatal("read-only failed probes stopped original child", got)
	}
	feed.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal("child was unexpectedly signaled", err)
	}
	reaped = true
	if got := observeProcess(s); got != "gone" {
		t.Fatal("original exit not observed", got)
	}
}

func TestHostNativeJournalObservationNoReplayAndHeldLease(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, d, s, r := receiptFixture()
	// The fixed historical boot cannot match the current native worker. This
	// fixture verifies journal observation, not a signed native scan lifecycle.
	host, err := ReadHost()
	if err != nil {
		t.Fatal(err)
	}
	if host.BootID == in.Selection.BootID {
		t.Fatal("fixture unexpectedly equals original native boot")
	}
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := tree.checkJobs(); err == nil {
		t.Fatal("queued root request ignored by upgrade")
	}
	if _, err := j.root.Lstat("run.lock"); !os.IsNotExist(err) {
		t.Fatal("read-only guard created run lease")
	}
	write := func(name string, v any) {
		t.Helper()
		raw, _ := json.Marshal(v)
		if err := j.WriteImmutable(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	write("dispatch.json", d)
	o, err := j.Observe(in)
	if err != nil || o.State != "starting" || o.TerminalVerified {
		t.Fatal(o.State, err)
	}
	if _, err := j.root.Lstat("run.lock"); !os.IsNotExist(err) {
		t.Fatal("starting observation created run lease")
	}
	lease, err := j.Lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	write("started.json", s)
	write("result.json", r)
	o, err = j.Observe(in)
	if err != nil || o.State != "settling" || o.TerminalVerified || o.RunLeaseFree {
		t.Fatal("result completed while original lease held", o.State, err)
	}
	if err := tree.checkJobs(); err == nil {
		t.Fatal("upgrade ignored held original lease")
	}
	lease.Close()
	o, err = j.Observe(in)
	if err != nil || !o.TerminalVerified || o.State != "complete" || o.Process != "gone" || o.Scope != "empty" {
		t.Fatal("retained typed terminal and stopped original identity not recognized", o, err)
	}
	if err := tree.checkJobs(); err != nil {
		t.Fatal("verified old original terminal blocked", err)
	}
	if err := j.WriteImmutable("result.json", []byte(`{"state":"complete"}`)); err == nil {
		t.Fatal("observation made immutable result overwritable")
	}
	if err := j.root.WriteFile("progress.pending", []byte(`{"interrupted":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Observe(in); err == nil {
		t.Fatal("interrupted pending progress treated as finished original")
	}
	if _, err := j.root.Lstat("progress.pending"); err != nil {
		t.Fatal("observer removed original pending evidence")
	}
}

func TestHostNativeScopeAndProcessParsingClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native scope verification not executed")
	}
	for _, group := range []string{"/", "/system.slice/../anything", "/system.slice/panel-disk-host-bad.scope", "/other/panel-disk-host-" + strings.Repeat("1", 32) + ".scope"} {
		if got := observeScope(group); got != "unknown" {
			t.Fatal("nonoriginal scope accepted", group, got)
		}
	}
	unit, _ := UnitName(strings.Repeat("1", 32), false)
	if got := observeScope("/system.slice/" + unit); got != "empty" {
		t.Fatal("fixed original missing scope cannot be independently observed", got)
	}
	for _, raw := range []string{"", "populated 0 populated 0", "frozen 0", "populated 2", "populated 0 unknown 0"} {
		if _, err := populated([]byte(raw)); err == nil {
			t.Fatal("ambiguous cgroup state accepted", raw)
		}
	}
	// comm may itself contain parentheses and spaces; field22 is after the
	// LAST closing delimiter, not strings.Fields(raw)[21].
	raw := "234 (a ) tricky ( name) S " + strings.Repeat("0 ", 18) + "987 0"
	if got, err := processTicks([]byte(raw), "234"); err != nil || got != "987" {
		t.Fatal(got, err)
	}
	if _, err := processTicks([]byte(raw), "235"); err == nil {
		t.Fatal("foreign PID stat accepted")
	}
}

func TestHostNativeProcessPIDFDSafeTermination(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native original-pidfd SIGTERM not executed; no device/production acceptance")
	}
	host, err := ReadHost()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := processSHA("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	input, feed, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer feed.Close()
	cmd := exec.Command(exe, "-test.run=^TestHostNativeProcessChild$")
	cmd.Env = append(os.Environ(), "PANEL_DISK_PROCESS_TEST_CHILD=fixed-source-only")
	cmd.Stdin = input
	ready, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		feed.Close()
		if !reaped {
			cmd.Wait()
		}
	})
	buf := make([]byte, 6)
	if _, err := io.ReadFull(ready, buf); err != nil || string(buf) != "ready\n" {
		t.Fatal("native child readiness unavailable", err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	raw, err := fixedKernelRead("/proc/"+pid+"/stat", 8192, unix.PROC_SUPER_MAGIC)
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processTicks(raw, pid)
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := fixedKernelRead("/proc/"+pid+"/cgroup", 4096, unix.PROC_SUPER_MAGIC)
	if err != nil || !strings.HasPrefix(string(cgroup), "0::") {
		t.Fatal(err)
	}
	s := Started{PID: pid, StartTicks: ticks, ExecutorSHA: sha, Policy: Policy{Host: host, Cgroup: strings.TrimSpace(strings.TrimPrefix(string(cgroup), "0::"))}}
	wrong := s
	wrong.ExecutorSHA = strings.Repeat("1", 64)
	if got := probeOriginalProcess(wrong, true); got != "unknown" {
		t.Fatal("unmatched executable was signaled", got)
	}
	wrong = s
	wrong.StartTicks = "1"
	if got := probeOriginalProcess(wrong, true); got != "gone" {
		t.Fatal("reused numeric PID signaled", got)
	}
	if got := observeProcess(s); got != "alive" {
		t.Fatal("rejected signals affected original child", got)
	}
	if got := probeOriginalProcess(s, true); got != "signaled" {
		t.Fatal("actual original pidfd SIGTERM unavailable", got)
	}
	err = cmd.Wait()
	reaped = true
	if err == nil || cmd.ProcessState == nil {
		t.Fatal("source fixture child did not receive native termination", err)
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatal("wrong native signal or process outcome", status)
	}
	if got := probeOriginalProcess(s, true); got != "gone" {
		t.Fatal("original reaped identity could be signaled/reused", got)
	}
}
