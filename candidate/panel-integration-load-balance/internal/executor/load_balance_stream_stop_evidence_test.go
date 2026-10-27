package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamStopExitRequiresOriginalSuccessfulNormalManagerExit(t *testing.T) {
	id := strings.Repeat("a", 32)
	raw := "Id=panel-load-balance-stream.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nMainPID=0\nControlPID=0\nInvocationID=" + id + "\nResult=success\nExecMainCode=1\nExecMainStatus=0\nRemainAfterExit=yes\n"
	if !streamStoppedExitMatches([]byte(raw), id) {
		t.Fatal("complete original normal exit rejected")
	}
	for _, wrong := range []string{"", strings.TrimSuffix(raw, "\n"), raw + "\x00", raw + "ExecMainStatus=0\n", raw + "Unrelated=1\n",
		strings.Replace(raw, "MainPID=0", "MainPID=219", 1), strings.Replace(raw, "ControlPID=0", "ControlPID=222", 1),
		strings.Replace(raw, "Code=1", "Code=2", 1), strings.Replace(raw, "Status=0", "Status=9", 1),
		strings.Replace(raw, "Result=success", "Result=oom-kill", 1), strings.Replace(raw, "State=active\n", "State=inactive\n", 1),
		strings.Replace(raw, "State=exited", "State=running", 1), strings.Replace(raw, "RemainAfterExit=yes", "RemainAfterExit=no", 1),
		strings.Replace(raw, id, strings.Repeat("b", 32), 1), strings.Replace(raw, "load-balance-stream.service", "other.service", 1)} {
		if streamStoppedExitMatches([]byte(wrong), id) {
			t.Fatal("missing/other invocation, abnormal exit or still-live worker accepted")
		}
	}
	for _, id := range []string{"", strings.Repeat("0", 32), strings.Repeat("A", 32), "../../unit"} {
		if streamStoppedExitMatches([]byte(raw), id) {
			t.Fatal("claimed invocation selected a stopped result")
		}
	}
}
