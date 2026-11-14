//go:build linux

package executor

import (
	"strings"
	"testing"
)

func TestRedisPersistenceInterpretsNativeReply(t *testing.T) {
	raw := strings.Join([]string{
		"# Persistence",
		"rdb_last_save_time:1794721921",
		"rdb_changes_since_last_save:17",
		"rdb_bgsave_in_progress:1",
		"rdb_last_bgsave_status:ok",
		"rdb_last_bgsave_time_sec:2",
		"aof_enabled:1",
		"aof_rewrite_in_progress:0",
		"aof_rewrite_scheduled:1",
		"aof_last_write_status:err",
		"aof_current_size:25315428376",
	}, "\r\n")
	id := strings.Repeat("a", 32)
	got, err := parseRedisPersistence(id, raw)
	if err != nil || got.InstanceID != id || got.LastSnapshot != 1794721921 || got.ChangesSinceLastSave != 17 || got.SnapshotDuration != 2 ||
		!got.SnapshotRunning || got.SnapshotStatus != "ok" || !got.AOFEnabled || got.AOFRewriteRunning ||
		!got.AOFRewriteScheduled || got.AOFWriteStatus != "err" {
		t.Fatalf("bad persistence interpretation: %+v, %v", got, err)
	}
	startup, err := parseRedisPersistence(id, strings.Replace(raw, "rdb_last_bgsave_time_sec:2", "rdb_last_bgsave_time_sec:-1", 1))
	if err != nil || startup.LastSnapshot != 0 || startup.SnapshotDuration != -1 {
		t.Fatalf("Redis startup time is not a recorded snapshot: %+v, %v", startup, err)
	}
	for before, after := range map[string]string{
		"aof_enabled:1":                  "aof_enabled:2",
		"rdb_changes_since_last_save:17": "rdb_changes_since_last_save:-17",
		"rdb_last_bgsave_status:ok":      "rdb_last_bgsave_status:unknown",
	} {
		if _, err := parseRedisPersistence(id, strings.Replace(raw, before, after, 1)); err == nil {
			t.Fatal("accepted invalid native persistence reply", after)
		}
	}
}
