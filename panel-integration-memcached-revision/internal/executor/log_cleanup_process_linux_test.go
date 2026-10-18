//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type siteLogChildInput struct {
	Root, StateDir, Report, Mode string
	Request                      core.LogCleanupRequest
}

type siteLogChildResult struct {
	PID    int
	Result core.LogCleanupResult
	Error  string
}

func TestLogCleanupLedgerIndependentProcessChild(t *testing.T) {
	raw := os.Getenv("PANEL_QA_LOG_CHILD")
	if raw == "" {
		t.Skip("private parent fixture required")
	}
	var in siteLogChildInput
	if json.Unmarshal([]byte(raw), &in) != nil || !strings.HasPrefix(in.Root, "/tmp/TestLogCleanup") || filepath.Clean(in.Root) != in.Root || in.StateDir != filepath.Join(in.Root, "state") || in.Report != filepath.Join(in.Root, "child-report.json") || (in.Mode != "replay" && in.Mode != "crash_after_rotation") {
		t.Fatal("invalid private child fixture")
	}
	if ownedRuntimePath(in.Root, true) != nil {
		t.Fatal("private child root identity invalid")
	}
	s := New(Config{StateDir: in.StateDir, SystemRoot: in.Root})
	var reopen func(context.Context) error
	if in.Mode == "crash_after_rotation" {
		reopen = func(context.Context) error {
			name := "panel-" + in.Request.SiteID + ".access.log"
			if e := os.WriteFile(filepath.Join(in.Root, "var/log/nginx", name), []byte("post-crash new bytes"), 0640); e != nil {
				return e
			}
			body, e := json.Marshal(struct{ PID int }{os.Getpid()})
			if e != nil {
				return e
			}
			file, e := os.OpenFile(in.Report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			_, e = file.Write(body)
			if e == nil {
				e = file.Sync()
			}
			file.Close()
			if e != nil {
				return e
			}
			select {} // Parent kills only this owned child after observing ready.
		}
	}
	out, e := s.guardedSiteLogCleanup(t.Context(), in.Request, time.Date(2026, 10, 8, 11, 0, 0, 0, time.UTC), reopen)
	result := siteLogChildResult{PID: os.Getpid(), Result: out}
	if e != nil {
		result.Error = e.Error()
	}
	file, e := os.OpenFile(in.Report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if e = json.NewEncoder(file).Encode(result); e != nil {
		t.Fatal(e)
	}
}

func launchSiteLogChild(t *testing.T, s *Service, in core.LogCleanupRequest, mode string) (*exec.Cmd, string) {
	t.Helper()
	report := filepath.Join(s.Config.SystemRoot, "child-report.json")
	body, e := json.Marshal(siteLogChildInput{s.Config.SystemRoot, s.Config.StateDir, report, mode, in})
	if e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	command := exec.Command(binary, "-test.run", "^TestLogCleanupLedgerIndependentProcessChild$", "-test.timeout", "30s")
	command.Env = append(os.Environ(), "PANEL_QA_LOG_CHILD="+string(body))
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	return command, report
}

func TestLogCleanupLedgerCompletedReplaySurvivesActualFreshPID(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "original bytes")
	result, e := s.guardedSiteLogCleanup(t.Context(), in, now, func(context.Context) error {
		siteLogFixtureWrite(t, filepath.Join(logs, name), "new writer bytes")
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	in.Attempt = 1
	command, report := launchSiteLogChild(t, s, in, "replay")
	if e = command.Wait(); e != nil {
		t.Fatal("fresh child failed", e)
	}
	body, e := os.ReadFile(report)
	if e != nil {
		t.Fatal(e)
	}
	var replay siteLogChildResult
	if e = json.Unmarshal(body, &replay); e != nil || replay.PID != command.Process.Pid || replay.PID == os.Getpid() || replay.Error != "" || !reflect.DeepEqual(replay.Result, result) {
		t.Fatal("new PID did not replay exact result", replay, e)
	}
	for suffix, want := range map[string]string{"": "new writer bytes", ".20261008-110000": "original bytes"} {
		if body, e := os.ReadFile(filepath.Join(logs, name+suffix)); e != nil || string(body) != want {
			t.Fatal("new PID repeated file operations", suffix, e)
		}
	}
	t.Logf("parent PID %d and fresh child PID %d verified identical persisted result with original/archive/new writer bytes preserved", os.Getpid(), replay.PID)
}

func TestLogCleanupLedgerActualProcessKilledAfterRotationNeverRepeatsUnknownWork(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	retired := name + ".20260901-100000"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "original bytes")
	siteLogFixtureWrite(t, filepath.Join(logs, retired), "retired bytes")
	command, report := launchSiteLogChild(t, s, in, "crash_after_rotation")
	t.Cleanup(func() { _ = command.Process.Kill() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		body, e := os.ReadFile(report)
		var ready struct{ PID int }
		if e == nil && json.Unmarshal(body, &ready) == nil && ready.PID == command.Process.Pid {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("private child did not reach durable rotation barrier")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if e := command.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	var exited *exec.ExitError
	if e := command.Wait(); !errors.As(e, &exited) || exited.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("owned child was not actually SIGKILLed", e)
	}
	for _, same := range []bool{true, false} {
		request := in
		if same {
			request.Attempt = 1
		} else {
			request.RequestID = core.ID()
		}
		if _, e := New(s.Config).guardedSiteLogCleanup(t.Context(), request, now.Add(time.Hour), nil); e == nil {
			t.Fatal("killed operation replayed", same)
		}
	}
	for suffix, want := range map[string]string{"": "post-crash new bytes", ".20261008-110000": "original bytes", ".20260901-100000": "retired bytes"} {
		if body, e := os.ReadFile(filepath.Join(logs, name+suffix)); e != nil || string(body) != want {
			t.Fatal("crash recovery lost bytes", suffix, e)
		}
	}
	out, e := s.inspectSiteLogCleanup(t.Context(), in.SiteID, in.RequestID)
	if e != nil || out.State != "running" || out.Result != nil || !out.ReadOnly {
		t.Fatal("killed operation misclassified as successful", out, e)
	}
	t.Logf("owned child PID %d actually SIGKILLed after durable rename barrier; old/new/archive/expired bytes preserved and same/new ID retries rejected", command.Process.Pid)
}
