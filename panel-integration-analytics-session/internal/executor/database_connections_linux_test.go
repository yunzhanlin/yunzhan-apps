//go:build linux

package executor

import "testing"

func TestParseMySQLConnections(t *testing.T) {
	if count, err := parseMySQLConnections("Threads_connected\t12"); err != nil || count != 12 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	for _, raw := range []string{"12", "Threads_running\t12", "Threads_connected\t-1", "Threads_connected\t1000001", "Threads_connected\tNaN", "Threads_connected\t2\textra"} {
		if _, err := parseMySQLConnections(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
