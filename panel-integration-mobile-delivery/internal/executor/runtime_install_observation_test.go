package executor

import (
	"strings"
	"testing"
)

func runtimeUnitObservationFixture(load, active, result, started, job string) string {
	return "LoadState=" + load + "\nActiveState=" + active + "\nResult=" + result + "\nExecMainStartTimestampMonotonic=" + started + "\nJob=" + job + "\n"
}

func TestRuntimeInstallCompleteUnitObservation(t *testing.T) {
	for _, row := range []struct {
		name, load, active, result, started, job, want string
	}{
		{"running", "loaded", "active", "success", "123", "", "running"},
		{"starting", "loaded", "activating", "success", "0", "2", "running"},
		{"pending", "loaded", "inactive", "success", "0", "2", "running"},
		{"stopping", "loaded", "deactivating", "success", "123", "", "running"},
		{"reload", "loaded", "reloading", "success", "123", "", "running"},
		{"refresh", "loaded", "refreshing", "success", "123", "", "running"},
		{"unstarted", "loaded", "inactive", "success", "0", "", "needs_attention"},
		{"missing_completion", "loaded", "inactive", "success", "123", "", "needs_attention"},
		{"failed_result", "loaded", "failed", "exit-code", "123", "", "failed"},
		{"stopped_signal", "loaded", "inactive", "signal", "123", "", "failed"},
		{"stopped_timeout", "loaded", "inactive", "timeout", "123", "", "failed"},
		{"oom", "loaded", "failed", "oom-kill", "123", "", "failed"},
		{"contradiction", "loaded", "failed", "success", "123", "", "needs_attention"},
		{"missing", "not-found", "inactive", "", "0", "", "needs_attention"},
		{"masked", "masked", "inactive", "success", "0", "", "needs_attention"},
	} {
		t.Run(row.name, func(t *testing.T) {
			v, err := decodeRuntimeInstallUnitObservation(runtimeUnitObservationFixture(row.load, row.active, row.result, row.started, row.job))
			if err != nil {
				t.Fatal(err)
			}
			state, detail := v.result("running")
			if state != row.want || (state == "running") != (detail == "") || state == "succeeded" {
				t.Fatal("unit observation forged a completed build", state, detail)
			}
		})
	}
}

func TestRuntimeInstallIncompleteUnknownUnitReadCannotMeanSuccess(t *testing.T) {
	base := runtimeUnitObservationFixture("loaded", "inactive", "success", "123", "")
	bad := []string{"", "\n", "LoadState=loaded\n", base + "Job=\n", base + "Unknown=yes\n", strings.Replace(base, "Result=success\n", "", 1),
		strings.Replace(base, "loaded", "guessed", 1), strings.Replace(base, "inactive", "guessed", 1),
		strings.Replace(base, "success", "guessed", 1), strings.Replace(base, "123", "-1", 1),
		strings.Replace(base, "123", "18446744073709551616", 1), strings.Replace(base, "Job=", "Job=unknown", 1),
		strings.Replace(base, "inactive", "inactive\x00", 1), strings.Replace(base, "inactive", "inactive ", 1),
		runtimeUnitObservationFixture("not-found", "active", "success", "0", ""), strings.Repeat("x", 4097)}
	for i, text := range bad {
		if _, err := decodeRuntimeInstallUnitObservation(text); err == nil {
			t.Fatal("partial or unknown service read trusted", i)
		}
	}
}
