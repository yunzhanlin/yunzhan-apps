package executor

import (
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const streamStoppedExitProperties = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainCode,ExecMainStatus,RemainAfterExit"

func streamStoppedExitMatches(raw []byte, invocation string) bool {
	if !core.ValidID(invocation) || invocation == strings.Repeat("0", 32) || len(raw) == 0 || len(raw) > 4096 ||
		!strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	want := map[string]string{
		"Id": loadbalancestream.ServiceUnitName, "LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
		"MainPID": "0", "ControlPID": "0", "InvocationID": invocation, "Result": "success",
		"ExecMainCode": "1", "ExecMainStatus": "0", "RemainAfterExit": "yes",
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
