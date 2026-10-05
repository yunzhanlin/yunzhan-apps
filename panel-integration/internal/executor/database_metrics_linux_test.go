//go:build linux

package executor

import "testing"

func TestParseDatabaseMetricsRejectsUnrequestedOrInvalidRows(t *testing.T) {
	wanted := map[string]bool{"website_db": true, "blog_db": true}
	rows, err := parseDatabaseMetrics("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "blog_db\tutf8mb4\t4096\nwebsite_db\tutf8mb4\t2048", wanted)
	if err != nil || len(rows) != 2 || rows[0].Bytes != 4096 || rows[1].Charset != "utf8mb4" {
		t.Fatalf("unexpected metrics: %+v %v", rows, err)
	}
	for _, raw := range []string{"private_db\tutf8mb4\t9", "blog_db\tutf8mb4\t-1", "blog_db\tutf8mb4\tinvalid", "blog_db\tutf8mb4"} {
		if _, err := parseDatabaseMetrics("id", raw, wanted); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
