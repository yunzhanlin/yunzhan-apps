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
