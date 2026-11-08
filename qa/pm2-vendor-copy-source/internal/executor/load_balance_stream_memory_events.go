package executor

import (
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamMemoryEvents struct {
	OOM        uint64 `json:"oom"`
	Kills      uint64 `json:"oom_kill"`
	GroupKills uint64 `json:"oom_group_kill"`
}

// Observed counters, not a health boolean or permission to reset a cgroup.
// A new worker PID after an OOM must not silently satisfy a reload witness.
func decodeStreamMemoryEvents(raw []byte) (loadBalanceStreamMemoryEvents, error) {
	var out loadBalanceStreamMemoryEvents
	if len(raw) == 0 || len(raw) > 4096 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return out, loadbalancestream.ErrService
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		v := strings.Split(line, " ")
		if len(v) != 2 || v[0] == "" || len(v[0]) > 64 || seen[v[0]] || len(seen) >= 32 {
			return out, loadbalancestream.ErrService
		}
		for _, c := range v[0] {
			if !(c >= 'a' && c <= 'z' || c == '_') {
				return out, loadbalancestream.ErrService
			}
		}
		n, err := strconv.ParseUint(v[1], 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != v[1] {
			return out, loadbalancestream.ErrService
		}
		seen[v[0]] = true
		switch v[0] {
		case "oom":
			out.OOM = n
		case "oom_kill":
			out.Kills = n
		case "oom_group_kill":
			out.GroupKills = n
		}
	}
	if !seen["oom"] || !seen["oom_kill"] {
		return out, loadbalancestream.ErrService
	}
	return out, nil
}
