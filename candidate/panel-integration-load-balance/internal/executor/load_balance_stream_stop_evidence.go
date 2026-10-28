package executor

import (
	"strconv"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const streamStoppedExitProperties = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainCode,ExecMainStatus,RemainAfterExit"
const streamStoppedPrunedExitProperties = streamStoppedExitProperties + ",OOMPolicy,ControlGroup"

// pidfd readiness can precede PID1's reap. This exact still-running original
// invocation is only a bounded wait state; it is never accepted as exit proof.
func streamStoppedAwaitingReapMatches(raw []byte, invocation string, master int) bool {
	if master < 2 || !core.ValidID(invocation) || invocation == strings.Repeat("0", 32) {
		return false
	}
	return streamExactManagerProperties(raw, map[string]string{
		"Id": loadbalancestream.ServiceUnitName, "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
		"MainPID": strconv.Itoa(master), "ControlPID": "0", "InvocationID": invocation, "Result": "success",
		"ExecMainCode": "0", "ExecMainStatus": "0", "RemainAfterExit": "yes",
	})
}

func streamStoppedExitMatches(raw []byte, invocation string) bool {
	return streamStoppedObservedExitMatches(raw, invocation, false)
}

// A disappeared cgroup is never a final counter observation. After the
// original held pidfds report exit, an exact retained clean PID1 invocation
// with OOMPolicy=stop and no ControlGroup is a separate form of exit evidence.
// OOM stop retains Result=oom-kill even when the master itself exits zero.
func streamStoppedPrunedExitMatches(raw []byte, invocation string) bool {
	return streamStoppedObservedExitMatches(raw, invocation, true)
}

func streamStoppedEvidenceMatches(raw []byte, invocation string, empty, pruned bool) bool {
	if empty == pruned {
		return false
	}
	if pruned {
		return streamStoppedPrunedExitMatches(raw, invocation)
	}
	return streamStoppedExitMatches(raw, invocation)
}

func streamStoppedObservedExitMatches(raw []byte, invocation string, pruned bool) bool {
	if !core.ValidID(invocation) || invocation == strings.Repeat("0", 32) || len(raw) == 0 || len(raw) > 4096 ||
		!strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	want := map[string]string{
		"Id": loadbalancestream.ServiceUnitName, "LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
		"MainPID": "0", "ControlPID": "0", "InvocationID": invocation, "Result": "success",
		"ExecMainCode": "1", "ExecMainStatus": "0", "RemainAfterExit": "yes",
	}
	if pruned {
		want["OOMPolicy"], want["ControlGroup"] = "stop", ""
	}
	return streamExactManagerProperties(raw, want)
}

func streamExactManagerProperties(raw []byte, want map[string]string) bool {
	if len(raw) == 0 || len(raw) > 4096 || len(want) == 0 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || value != expected {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}
