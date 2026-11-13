//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestLoadBalanceStreamAccountCompletionAfterSystemdGarbageCollection(t *testing.T) {
	state := map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "ExecMainStatus": "0", "Result": "success", "InvocationID": ""}
	if !streamInstallAccountChildTerminated(state) {
		t.Fatal("successful collected unit became an account failure")
	}
	state["InvocationID"] = strings.Repeat("a", 32)
	if !streamInstallAccountChildTerminated(state) {
		t.Fatal("successful retained invocation refused")
	}
	for key, bad := range map[string]string{"LoadState": "not-found", "ActiveState": "active", "SubState": "failed", "MainPID": "42", "ControlPID": "42", "ExecMainStatus": "1", "Result": "exit-code", "InvocationID": strings.Repeat("0", 32)} {
		old := state[key]
		state[key] = bad
		if streamInstallAccountChildTerminated(state) {
			t.Fatal("collection accepted invalid completion", key)
		}
		state[key] = old
	}
	state["InvocationID"] = "ambiguous"
	if streamInstallAccountChildTerminated(state) {
		t.Fatal("malformed invocation accepted")
	}
	delete(state, "InvocationID")
	state["Foreign"] = ""
	if streamInstallAccountChildTerminated(state) {
		t.Fatal("missing invocation property became a collected invocation")
	}
}

// Exercise actual PID1 lifetime and GC, without account/NSS/application effects.
// A Root host with systemd is required; ordinary non-Root package tests cannot
// supply this witness. The normal native Root CI suite executes it on both CPUs.
func TestLoadBalanceStreamAccountCompletionNativeSystemdGarbageCollection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root systemd witness required")
	}
	comm, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(comm)) != "systemd" {
		t.Skip("actual systemd PID1 required")
	}
	unit := "panel-own-lbstream-completion-" + core.ID() + ".service"
	path := filepath.Join("/run/systemd/system", unit)
	raw := []byte("[Unit]\nDescription=Owned account completion metadata regression\n[Service]\nType=exec\nUser=root\nExecStart=/usr/bin/true\nRestart=no\nRemainAfterExit=no\nNoNewPrivileges=yes\nPrivateNetwork=yes\nProtectSystem=strict\n")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The once-only true command has terminated. Delete only this owned fixture;
		// never reset/restart/stop a panel or any preinstalled application unit.
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := programQueueCommand(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := programQueueCommand(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := programQueueCommand(ctx, "/usr/bin/systemctl", "--wait", "start", unit); err != nil {
		t.Fatal(err)
	}
	state, err := streamInstallUnitProperties(ctx, unit)
	if err != nil || !streamInstallAccountChildTerminated(state) {
		t.Fatal("actual successful unit refused", state, err)
	}
	t.Logf("actual post-wait metadata: %#v", state)
}

func TestLoadBalanceStreamRetainedRefusalRequiresBothOriginalUnitsIdle(t *testing.T) {
	job := core.LoadBalanceStreamUpgradeJob{
		Authority: core.LoadBalanceStreamInstallAuthority{JobID: core.ID()},
		State:     "needs_attention", RetainedRefusal: core.LoadBalanceStreamInstallNginx,
	}
	idle := func() map[string]string {
		return map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "ExecMainStatus": "0", "Result": "success", "InvocationID": ""}
	}
	var observed []string
	if err := verifyRetainedLoadBalanceStreamPreflight(t.Context(), job, func(_ context.Context, unit string) (map[string]string, error) {
		observed = append(observed, unit)
		return idle(), nil
	}, false); err != nil || len(observed) != 2 ||
		observed[0] != "panel-lbstream-install@"+job.Authority.JobID+".service" ||
		observed[1] != "panel-lbstream-account-create@"+job.Authority.JobID+".service" {
		t.Fatal("original unit identities were not both checked", observed, err)
	}
	for key, value := range map[string]string{"LoadState": "not-found", "ActiveState": "active", "ControlPID": "42", "InvocationID": strings.Repeat("a", 32)} {
		t.Run(key, func(t *testing.T) {
			calls := 0
			err := verifyRetainedLoadBalanceStreamPreflight(t.Context(), job, func(_ context.Context, _ string) (map[string]string, error) {
				calls++
				state := idle()
				if calls == 2 {
					state[key] = value
				}
				return state, nil
			}, false)
			if err == nil || calls != 2 {
				t.Fatal("unsafe original child unit accepted", key, err)
			}
		})
	}
}

func TestLoadBalanceStreamRetainedParentExitRequiresNoLiveChild(t *testing.T) {
	job := core.LoadBalanceStreamUpgradeJob{
		Authority: core.LoadBalanceStreamInstallAuthority{JobID: core.ID()},
		State:     "needs_attention", RetainedRefusal: core.LoadBalanceStreamRetainedParentExit,
	}
	for _, scenario := range []string{"actual-exit", "old-result-collected", "signal", "live-child", "unknown-exit", "failed-child-with-account", "failed-child-without-account"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			err := verifyRetainedLoadBalanceStreamPreflight(t.Context(), job, func(_ context.Context, unit string) (map[string]string, error) {
				calls++
				state := map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "ExecMainStatus": "0", "Result": "success", "InvocationID": ""}
				if calls == 1 && scenario != "old-result-collected" ||
					calls == 2 && (scenario == "failed-child-with-account" || scenario == "failed-child-without-account") {
					state["ActiveState"], state["SubState"], state["Result"], state["ExecMainStatus"] = "failed", "failed", "exit-code", "1"
					state["InvocationID"] = strings.Repeat("a", 32)
				}
				switch scenario {
				case "signal":
					if calls == 1 {
						state["Result"] = "signal"
					}
				case "live-child":
					if calls == 2 {
						state["MainPID"] = "42"
					}
				case "unknown-exit":
					if calls == 1 {
						state["ExecMainStatus"] = "2"
					}
				}
				return state, nil
			}, scenario == "failed-child-with-account")
			if (err == nil) != (scenario == "actual-exit" || scenario == "old-result-collected" || scenario == "failed-child-with-account") {
				t.Fatal("unexpected historical result", calls, err)
			}
		})
	}
}
