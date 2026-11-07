package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamStopOriginalManagerReapIsOnlyBoundedWait(t *testing.T) {
	id := strings.Repeat("a", 32)
	raw := "Id=panel-load-balance-stream.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=219\nControlPID=0\nInvocationID=" + id + "\nResult=success\nExecMainCode=0\nExecMainStatus=0\nRemainAfterExit=yes\n"
	if !streamStoppedAwaitingReapMatches([]byte(raw), id, 219) || streamStoppedExitMatches([]byte(raw), id) || streamStoppedPrunedExitMatches([]byte(raw), id) {
		t.Fatal("original pending reap must wait without becoming completed exit evidence")
	}
	for _, bad := range []string{raw + "MainPID=219\n", strings.TrimSuffix(raw, "\n"),
		strings.Replace(raw, id, strings.Repeat("b", 32), 1), strings.Replace(raw, "MainPID=219", "MainPID=222", 1),
		strings.Replace(raw, "Result=success", "Result=oom-kill", 1), strings.Replace(raw, "Status=0", "Status=9", 1),
		strings.Replace(raw, "Code=0", "Code=1", 1), strings.Replace(raw, "ControlPID=0", "ControlPID=225", 1),
		strings.Replace(raw, "State=running", "State=failed", 1)} {
		if streamStoppedAwaitingReapMatches([]byte(bad), id, 219) {
			t.Fatal("changed, failed or other invocation cannot extend original reap wait")
		}
	}
}

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

func TestLoadBalanceStreamStopPrunedCgroupKeepsDistinctManagerAndOOMProof(t *testing.T) {
	id := strings.Repeat("a", 32)
	legacy := "Id=panel-load-balance-stream.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nMainPID=0\nControlPID=0\nInvocationID=" + id + "\nResult=success\nExecMainCode=1\nExecMainStatus=0\nRemainAfterExit=yes\n"
	pruned := legacy + "OOMPolicy=stop\nControlGroup=\n"
	if !streamStoppedEvidenceMatches([]byte(legacy), id, true, false) || !streamStoppedEvidenceMatches([]byte(pruned), id, false, true) {
		t.Fatal("the two complete original exit evidence types must remain distinct")
	}
	for _, flags := range [][2]bool{{false, false}, {true, true}} {
		if streamStoppedEvidenceMatches([]byte(pruned), id, flags[0], flags[1]) {
			t.Fatal("missing or contradictory cgroup evidence accepted")
		}
	}
	if streamStoppedEvidenceMatches([]byte(legacy), id, false, true) || streamStoppedEvidenceMatches([]byte(pruned), id, true, false) {
		t.Fatal("old counter proof and manager-pruned evidence were interchangeable")
	}
	for _, wrong := range []string{legacy, strings.TrimSuffix(pruned, "\n"), pruned + "OOMPolicy=stop\n", pruned + "Extra=yes\n",
		strings.Replace(pruned, "OOMPolicy=stop", "OOMPolicy=continue", 1), strings.Replace(pruned, "OOMPolicy=stop", "OOMPolicy=kill", 1),
		strings.Replace(pruned, "ControlGroup=\n", "ControlGroup=/system.slice/panel-load-balance-stream.service\n", 1),
		strings.Replace(pruned, "Result=success", "Result=oom-kill", 1), strings.Replace(pruned, "Result=success", "Result=exit-code", 1),
		strings.Replace(pruned, "Code=1", "Code=2", 1), strings.Replace(pruned, "Status=0", "Status=9", 1),
		strings.Replace(pruned, "MainPID=0", "MainPID=219", 1), strings.Replace(pruned, id, strings.Repeat("b", 32), 1),
		strings.Replace(pruned, "State=exited", "State=failed", 1), strings.Replace(pruned, "RemainAfterExit=yes", "RemainAfterExit=no", 1)} {
		if streamStoppedPrunedExitMatches([]byte(wrong), id) {
			t.Fatal("missing, conflicting, other, still-live or OOM exit accepted", wrong)
		}
	}
	// An OOM-killed child can leave a cleanly exited master. Result must still
	// reject that invocation; ExecMainStatus=0 alone is never success evidence.
	childOOM := strings.Replace(pruned, "Result=success", "Result=oom-kill", 1)
	if !strings.Contains(childOOM, "ExecMainCode=1\nExecMainStatus=0\n") || streamStoppedPrunedExitMatches([]byte(childOOM), id) {
		t.Fatal("clean master concealed a child OOM")
	}
}
