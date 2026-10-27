package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamMemoryEventsKeepOriginalOOMCountersWithoutResetOrHealthClaim(t *testing.T) {
	for _, raw := range []string{"low 0\nhigh 23\nmax 1\noom 2\noom_kill 1\n", "low 0\nhigh 23\nmax 1\noom 2\noom_kill 1\noom_group_kill 1\n"} {
		v, err := decodeStreamMemoryEvents([]byte(raw))
		if err != nil || v.OOM != 2 || v.Kills != 1 || v.GroupKills != uint64(strings.Count(raw, "oom_group_kill")) {
			t.Fatal("actual historical OOM counters erased or rejected", v, err)
		}
	}
	for _, raw := range []string{"", "oom 0\n", "oom_kill 0\n", "oom 0\noom_kill 0\noom_kill 0\n", "oom 0\noom_kill -1\n", "oom 00\noom_kill 0\n", "oom 0\noom_kill 0", "oom 0\noom_kill 0\r\n", "oom 0\nOOM_kill 0\n", "oom 0\noom_kill 18446744073709551616\n", "oom 0\noom_kill 0\n\n"} {
		if _, err := decodeStreamMemoryEvents([]byte(raw)); err == nil {
			t.Fatal("missing/duplicate/malformed OOM data accepted", raw)
		}
	}
}
