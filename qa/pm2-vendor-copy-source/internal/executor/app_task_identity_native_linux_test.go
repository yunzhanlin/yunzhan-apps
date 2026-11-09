//go:build linux

package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Real kernel/proc/pidfd and numeric non-root child in a fresh private QA unit.
// Its PM2-shaped cgroup is a fixture, not a deployed PM2 application or cold
// boot. Eligible Task setup is a real signed-registry worker installation
// completed before spawning the owned child; neither is all-50 acceptance.
func TestTaskProcessIdentityNative(t *testing.T) {
	if os.Getenv("PANEL_QA_TASK_IDENTITY_NATIVE") != "1" {
		t.Skip("explicit private task identity fixture required")
	}
	const base = "/run/panel-task-identity24atu"
	var marker struct {
		Format int    `json:"format"`
		Mode   string `json:"mode"`
		Unit   string `json:"unit"`
		UID    uint32 `json:"uid"`
		GID    uint32 `json:"gid"`
	}
	if os.Geteuid() != 0 || readAnalyticsHTMLPrivateJSON(filepath.Join(base, "fixture.json"), 2048, &marker) != nil || marker.Format != 1 || marker.UID == 0 || marker.GID == 0 || (marker.Mode != "eligible" && marker.Mode != "unmanaged") {
		t.Fatal("unverified private native task fixture")
	}
	wanted := `^panel-pm2@qa-task24atu-[a-f0-9]{8}\.service$`
	if marker.Mode == "unmanaged" {
		wanted = `^panel-own-task24atu-unmanaged-[a-f0-9]{8}\.service$`
	}
	if !regexp.MustCompile(wanted).MatchString(marker.Unit) {
		t.Fatal("unowned QA unit")
	}
	parentGroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(parentGroup), "0::/") || strings.Count(string(parentGroup), "\n") != 1 || filepath.Base(strings.TrimSuffix(strings.TrimPrefix(string(parentGroup), "0::"), "\n")) != marker.Unit {
		t.Fatal("native fixture is not in its exact original QA cgroup")
	}
	var authenticatedSignal func(context.Context, core.AppModuleInput) (any, error)
	if marker.Mode == "eligible" {
		// Install the actual application before creating a process to control.
		// Setup and child phases each retain a 15-second context; the enclosing
		// native test remains limited to 45 seconds and its unit to 60 seconds.
		setupCtx, cancelSetup := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelSetup()
		authenticatedSignal = prepareTaskNativeAuthenticatedSignal(t, setupCtx, base)
		if setupCtx.Err() != nil {
			t.Fatal("actual signed Task installation setup exceeded its 15-second context", setupCtx.Err())
		}
		cancelSetup()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// The root QA supervisor has only its original six bounded capabilities.
	// A UID change alone does not clear CapInh. The non-root fixture voluntarily
	// drops inheritable/ambient bits before sleeping; policy still requires C0.
	child := exec.CommandContext(ctx, "/usr/bin/setpriv", "--inh-caps=-all", "--ambient-caps=-all", "--", "/usr/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: marker.UID, Gid: marker.GID, Groups: []uint32{marker.GID}}}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill() // only this newly spawned owned QA child
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-wait:
		case <-time.After(time.Second):
		}
	})
	pid := child.Process.Pid
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	var original procSample
	for i := 0; i < 100; i++ {
		body, readErr := os.ReadFile(statPath)
		if readErr == nil {
			original, err = parseProcStat(pid, string(body), uint64(os.Getpagesize()))
			status, statusErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
			if err == nil && original.StartTime > 0 && statusErr == nil && taskSafeProcessStatus(string(status), marker.UID) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if original.StartTime == 0 {
		t.Fatal("own native child startup identity unavailable")
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil || !taskSafeProcessStatus(string(status), marker.UID) {
		t.Fatal("actual child did not drop to original numeric UID, C0 and NNP1")
	}
	svc := New(Config{})
	if out, err := svc.moduleTasks(ctx, "terminate", core.AppModuleInput{PID: pid, StartTime: original.StartTime + 1}); err == nil || out != nil || unix.Kill(pid, 0) != nil {
		t.Fatal("stale identity signalled own child", out, err)
	}
	if out, err := svc.moduleTasks(ctx, "terminate", core.AppModuleInput{PID: os.Getpid(), StartTime: 1}); err == nil || out != nil {
		t.Fatal("root fixture process signalled", out, err)
	}
	if out, err := svc.moduleTasks(ctx, "terminate", core.AppModuleInput{PID: 1, StartTime: 1}); err == nil || out != nil {
		t.Fatal("PID 1 accepted", out, err)
	}
	closed, closeNow := context.WithCancel(ctx)
	closeNow()
	if out, err := svc.moduleTasks(closed, "terminate", core.AppModuleInput{PID: pid, StartTime: original.StartTime}); err == nil || out != nil || unix.Kill(pid, 0) != nil {
		t.Fatal("cancelled request signalled child", out, err)
	}
	input := core.AppModuleInput{PID: pid, StartTime: original.StartTime}
	var out any
	var signalErr error
	if marker.Mode == "eligible" {
		out, signalErr = authenticatedSignal(ctx, input)
	} else {
		out, signalErr = svc.moduleTasks(ctx, "terminate", input)
	}
	accepted, nativeExit := false, false
	if marker.Mode == "eligible" {
		identity, err := readTaskProcessIdentity("/proc", os.Getpid())
		if err != nil || identity.SafeUser || identity.UID != 0 {
			t.Fatal("root task permission was not independently refused", identity, err)
		}
		value, ok := out.(map[string]any)
		if signalErr != nil || !ok || len(value) != 4 || value["pid"] != float64(pid) || value["signal"] != "SIGTERM" || value["signal_accepted"] != true || value["exit_verified"] != false {
			t.Fatal("actual SIGTERM result is not the closed original signal receipt", out, signalErr)
		}
		accepted = true
		select {
		case err := <-wait:
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("actual child termination not observed", err)
			}
			state, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !state.Signaled() || state.Signal() != syscall.SIGTERM {
				t.Fatal("actual child did not exit by original SIGTERM", exit)
			}
			nativeExit = true
		case <-ctx.Done():
			t.Fatal("actual signal exit not verified before original deadline")
		}
	} else if signalErr == nil || out != nil || unix.Kill(pid, 0) != nil {
		t.Fatal("unmanaged numeric child received a production signal", out, signalErr)
	}
	if err := moduleWrite(filepath.Join(base, "acceptance.json"), map[string]any{"passed": true, "mode": marker.Mode, "unit": marker.Unit, "actual_numeric_uid": marker.UID, "actual_child_c0_nnp1": true, "actual_stale_identity_refused_child_alive": true, "actual_cancelled_identity_refused_child_alive": true, "root_and_pid1_refused": true, "actual_pidfd_sigterm_accepted": accepted, "actual_native_child_sigterm_exit_separately_verified": nativeExit, "signal_reply_itself_does_not_certify_exit": true, "pm2_cgroup_is_fixture_not_deployed_app": true, "core_http_verified": marker.Mode == "eligible", "actual_core_unix_executor_original_signal_and_audits": marker.Mode == "eligible", "actual_task_installed_via_signed_registry_worker": marker.Mode == "eligible", "cold_boot_verified": false, "main_panel_changed": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual bounded native task identity, numeric non-root C0/NNP1, stale/cancel/root/PID1 refusal and original pidfd SIGTERM policy; eligible case uses actual Core/Unix/audits, cgroup is QA fixture not real PM2 deployment; eligible installation uses official signed catalog and actual Core worker")
}
