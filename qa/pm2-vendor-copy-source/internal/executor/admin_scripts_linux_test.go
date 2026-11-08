//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func adminScriptTestDirs(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	tasks := filepath.Join(base, "tasks")
	for _, path := range []string{state, filepath.Join(tasks, "jobs"), filepath.Join(tasks, "work")} {
		if e := os.MkdirAll(path, 0750); e != nil {
			t.Fatal(e)
		}
	}
	return state, tasks
}

func TestAdminScriptReceiptPreventsDuplicateExecution(t *testing.T) {
	state, tasks := adminScriptTestDirs(t)
	in := core.AdminScriptRequest{JobID: core.ID(), Script: "echo safe\n", TimeoutSeconds: 5}
	in.ScriptSHA256 = core.Hash(in.Script)
	calls := 0
	runner := func(_ context.Context, path string, timeout int) (string, bool, error) {
		calls++
		if timeout != 5 {
			t.Fatal("timeout changed", timeout)
		}
		content, e := os.ReadFile(path)
		if e != nil || string(content) != in.Script {
			t.Fatal("script snapshot changed", string(content), e)
		}
		return "safe output", false, nil
	}
	first, e := executeAdminScriptAt(context.Background(), in, state, tasks, os.Getuid(), os.Getgid(), runner)
	if e != nil || first.State != "completed" || first.Output != "safe output" {
		t.Fatal(first, e)
	}
	second, e := executeAdminScriptAt(context.Background(), in, state, tasks, os.Getuid(), os.Getgid(), runner)
	if e != nil || second.Output != first.Output || calls != 1 {
		t.Fatal("completed receipt did not deduplicate", second, calls, e)
	}
}

func TestAdminScriptFirstRunCreatesPrivateReceiptDirectory(t *testing.T) {
	state, tasks := adminScriptTestDirs(t)
	if e := os.Remove(state); e != nil {
		t.Fatal(e)
	}
	in := core.AdminScriptRequest{JobID: core.ID(), Script: "echo first", TimeoutSeconds: 5}
	in.ScriptSHA256 = core.Hash(in.Script)
	_, e := executeAdminScriptAt(context.Background(), in, state, tasks, os.Getuid(), os.Getgid(), func(context.Context, string, int) (string, bool, error) { return "first", false, nil })
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(state)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("receipt directory permissions", info, e)
	}
}

func TestAdminScriptStartedReceiptRefusesReplay(t *testing.T) {
	state, tasks := adminScriptTestDirs(t)
	in := core.AdminScriptRequest{JobID: core.ID(), Script: "echo maybe\n", TimeoutSeconds: 5}
	in.ScriptSHA256 = core.Hash(in.Script)
	receipt := adminScriptReceipt{JobID: in.JobID, ScriptSHA256: in.ScriptSHA256, State: "started", Result: core.AdminScriptResult{State: "started", StartedAt: core.Now()}}
	if e := writeAdminScriptReceipt(filepath.Join(state, in.JobID+".json"), receipt); e != nil {
		t.Fatal(e)
	}
	_, e := executeAdminScriptAt(context.Background(), in, state, tasks, os.Getuid(), os.Getgid(), func(context.Context, string, int) (string, bool, error) {
		t.Fatal("ambiguous script was replayed")
		return "", false, errors.New("unreachable")
	})
	if e == nil {
		t.Fatal("ambiguous started receipt was accepted")
	}
}
