//go:build linux

package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamProgrammeReadRequiresAllStrictStoppedWriterFields(t *testing.T) {
	for _, unit := range streamProgrammeWriters {
		raw := "Id=" + unit + "\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled\nMainPID=0\nControlPID=0\nControlGroup=\nResult=success\n"
		if !streamProgrammeStoppedWriter(raw, unit) {
			t.Fatal("strictly stopped writer refused", unit)
		}
		for _, bad := range []string{"", raw[:len(raw)-1], raw + "MainPID=0\n", raw + "Unknown=true\n", strings.Replace(raw, "Id="+unit, "Id=other.service", 1), strings.Replace(raw, "loaded", "not-found", 1), strings.Replace(raw, "inactive", "active", 1), strings.Replace(raw, "dead", "failed", 1), strings.Replace(raw, "enabled", "masked", 1), strings.Replace(raw, "MainPID=0", "MainPID=22", 1), strings.Replace(raw, "ControlPID=0", "ControlPID=22", 1), strings.Replace(raw, "ControlGroup=", "ControlGroup=/system.slice/"+unit, 1), strings.Replace(raw, "success", "exit-code", 1), strings.Replace(raw, "Result=success\n", "", 1)} {
			if streamProgrammeStoppedWriter(bad, unit) {
				t.Fatal("partial, live, failed or ambiguous writer accepted", unit, bad)
			}
		}
	}
}

func TestLoadBalanceStreamProgrammeReadRefusesScheduledWritersAndRecovery(t *testing.T) {
	if !streamProgrammeNoWriterJobs("") || !streamProgrammeNoWriterJobs("17 unrelated.service start running\n") {
		t.Fatal("complete unrelated job inventory refused")
	}
	for _, unit := range append(streamProgrammeWriters[:], "panel-mysql-overwrite-recovery.timer", "panel-mysql-overwrite-recovery.service") {
		if streamProgrammeNoWriterJobs("17 " + unit + " start waiting\n") {
			t.Fatal("scheduled writer/recovery accepted", unit)
		}
	}
	for _, raw := range []string{"not-a-job\n", "017 unrelated.service start running\n", "17 unrelated.service start running\n17 another.service stop waiting\n", "17 unrelated.service start\n", "17 unrelated.service start running\r\n"} {
		if streamProgrammeNoWriterJobs(raw) {
			t.Fatal("ambiguous job inventory accepted")
		}
	}
}
