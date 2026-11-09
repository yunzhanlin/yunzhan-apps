//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestProgramUpgradeQueuesPlatformMaintenanceOriginalJournal(t *testing.T) {
	for _, scenario := range []string{"completed", "failed", "started-only", "orphan-result", "no-lock", "held-lock", "changed-request", "false-health", "duplicate-field", "unknown-entry", "unsafe-mode", "hardlink", "symlink", "foreign-owner"} {
		t.Run(scenario, func(t *testing.T) {
			root := programQueueFixture(t)
			relative := "var/lib/panel-executor/platform-maintenance-jobs"
			id := core.ID()
			input := core.PlatformMaintenanceInput{RequestID: id, Command: "nginx-reload", ExpectedPlanSHA: strings.Repeat("e", 64), Confirm: "RELOAD NGINX " + strings.Repeat("e", 64)}
			req := core.PlatformMaintenanceNativeRequest{Format: 1, GrantID: strings.Repeat("a", 64), ActorID: core.ID(), Input: input}
			start := core.PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: core.PlatformMaintenanceRequestSHA(req), State: "started", Outcome: "unknown"}
			terminal := start
			terminal.State, terminal.Outcome = "completed", "reload_signal_submitted"
			if scenario == "failed" {
				terminal.State, terminal.Outcome = "failed", "command_failed"
			}
			if scenario == "changed-request" {
				terminal.Request.ActorID = core.ID()
				terminal.RequestSHA = core.PlatformMaintenanceRequestSHA(terminal.Request)
			}
			if scenario == "false-health" {
				terminal.Outcome = "all_websites_healthy"
			}
			dir := filepath.Join(root, relative)
			if e := os.MkdirAll(dir, 0700); e != nil {
				t.Fatal(e)
			}
			requestPath := filepath.Join(dir, id+".request.json")
			resultPath := filepath.Join(dir, id+".result.json")
			for path, v := range map[string]core.PlatformMaintenanceRecord{requestPath: start, resultPath: terminal} {
				if path == requestPath && scenario == "orphan-result" || path == resultPath && scenario == "started-only" {
					continue
				}
				raw, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				if path == resultPath && scenario == "duplicate-field" {
					raw = append([]byte(`{"format":1,`), raw[1:]...)
				}
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			lockPath := filepath.Join(dir, id+".lock")
			if scenario != "no-lock" {
				if e := os.WriteFile(lockPath, nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch scenario {
			case "held-lock":
				f, e := os.OpenFile(lockPath, os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
					t.Fatal(e)
				}
			case "unknown-entry":
				if e := os.WriteFile(filepath.Join(dir, "unowned.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "unsafe-mode":
				if e := os.Chmod(resultPath, 0644); e != nil {
					t.Fatal(e)
				}
			case "foreign-owner":
				if e := os.Chown(resultPath, 65534, 65534); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(resultPath, filepath.Join(root, "outside-result")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				outside := filepath.Join(root, "outside-result")
				if e := os.Rename(resultPath, outside); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(outside, resultPath); e != nil {
					t.Fatal(e)
				}
			}
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			wantError := scenario != "completed" && scenario != "failed"
			if (err != nil) != wantError {
				t.Fatalf("scenario %s: %v", scenario, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("upgrade observer changed original maintenance journal")
			}
		})
	}
}
