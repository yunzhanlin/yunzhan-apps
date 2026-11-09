//go:build linux

package executor

import (
	"strings"
	"testing"
)

func TestThreatIDSSyntaxResultRequiresCurrentSuccessfulExecution(t *testing.T) {
	v := "ExecMainStartTimestampMonotonic=100\nExecMainCode=1\nExecMainStatus=0\nActiveState=active\nSubState=exited\nMainPID=0\n"
	if err := threatIDSSyntaxResult(v, 99, 101); err != nil {
		t.Fatal(err)
	}
	if threatIDSSyntaxResult("ExecMainCode=\n"+v, 99, 101) == nil {
		t.Fatal("empty then duplicate status accepted")
	}
	for _, bad := range []string{"", strings.Replace(v, "=100", "=98", 1), strings.Replace(v, "=100", "=102", 1), strings.Replace(v, "=100", "=0100", 1), strings.Replace(v, "ExecMainCode=1", "ExecMainCode=0", 1), strings.Replace(v, "ExecMainStatus=0", "ExecMainStatus=1", 1), strings.Replace(v, "ActiveState=active", "ActiveState=inactive", 1), strings.Replace(v, "exited", "running", 1), strings.Replace(v, "MainPID=0", "MainPID=2", 1), v + "ActiveState=active\n", v + "Unknown=yes\n", strings.Replace(v, "ExecMainStatus=0\n", "", 1)} {
		if threatIDSSyntaxResult(bad, 99, 101) == nil {
			t.Fatal("old/skipped/failed/malformed check accepted", bad)
		}
	}
}

func TestThreatIDSSyntaxIdleNeverStopsAnUnknownRunningParser(t *testing.T) {
	for _, state := range []string{"ActiveState=active\nSubState=exited\nMainPID=0\n", "MainPID=0\nActiveState=inactive\nSubState=dead\n", "MainPID=0\nActiveState=failed\nSubState=failed\n"} {
		if !threatIDSSyntaxIdle(state) {
			t.Fatal("known completed parser state refused", state)
		}
	}
	for _, state := range []string{"", "ActiveState=active\nSubState=running\nMainPID=2\n", "ActiveState=active\nSubState=exited\nMainPID=2\n", "MainPID=0\nActiveState=inactive\n", "MainPID=0\nActiveState=inactive\nSubState=dead\nMainPID=0\n"} {
		if threatIDSSyntaxIdle(state) {
			t.Fatal("unknown/running parser accepted", state)
		}
	}
}
