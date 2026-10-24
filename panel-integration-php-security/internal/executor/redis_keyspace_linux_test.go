//go:build linux

package executor

import "testing"

func TestParseRedisKeyspace(t *testing.T) {
	rows := parseRedisKeyspace("# Server\r\nredis_version:8.2.10\r\n# Keyspace\r\ndb2:keys=9,expires=3,avg_ttl=4800\r\ndb0:keys=2,expires=0,avg_ttl=0\r\ndb16:keys=999\r\ndb4:keys=bad\r\n")
	if len(rows) != 2 || rows[0].Index != 0 || rows[0].Keys != 2 || rows[1].Index != 2 || rows[1].Keys != 9 || rows[1].Expires != 3 || rows[1].AverageTTL != 4800 {
		t.Fatalf("keyspace: %+v", rows)
	}
	if empty := parseRedisKeyspace("# Keyspace\r\n"); len(empty) != 1 || empty[0].Index != 0 || empty[0].Keys != 0 {
		t.Fatalf("empty: %+v", empty)
	}
}
