//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func lbTrafficNativeRead(t *testing.T, s *Service, query string, want int) core.LoadBalanceTrafficFeed {
	t.Helper()
	mux := http.NewServeMux()
	s.moduleAlertRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/load-balance-traffic-alert-events"+query, nil))
	if w.Code != want {
		t.Fatal("unexpected traffic feed", w.Code, w.Body.String())
	}
	var f core.LoadBalanceTrafficFeed
	if want == 200 && json.Unmarshal(w.Body.Bytes(), &f) != nil {
		t.Fatal("invalid JSON feed")
	}
	return f
}
func TestLoadBalanceTrafficNativeReadsValidatedWholeHistoryWithoutCommandsOrPrivateData(t *testing.T) {
	s, tx, p, before := lbHistoryFixture(t)
	old := lbTrafficNativeRead(t, s, "", 200)
	if old.Available || len(old.Records) > 0 {
		t.Fatal("old version acquired scope")
	}
	lbAlertNativeInstall(t, s, "1.8.4")
	f := lbTrafficNativeRead(t, s, "", 200)
	if !f.Available || len(f.Records) != 1 || f.Records[0].ID != tx.ID || f.Records[0].State != "committed" || f.WorkerState != "unknown" {
		t.Fatal(f)
	}
	raw, _ := json.Marshal(f)
	for _, private := range []string{tx.Domain, s.Config.SecurityDir, "127.0.0.1", string(tx.Changes[0].NextData), "ca_pem"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private evidence leaked", private)
		}
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("source read rewrote transaction")
	}
	lbTrafficNativeRead(t, s, "?path=/arbitrary", 400)
	restarted := New(s.Config)
	again := lbTrafficNativeRead(t, restarted, "", 200)
	next, _ := json.Marshal(again)
	if !bytes.Equal(raw, next) {
		t.Fatal("restart changed persistent transaction identity")
	}
}
func TestLoadBalanceTrafficNativePendingNeverRecoversOrPretendsCommitted(t *testing.T) {
	s, tx, _, _ := lbHistoryFixture(t)
	lbAlertNativeInstall(t, s, "1.8.4")
	if e := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(s.loadBalancePendingPath())
	f := lbTrafficNativeRead(t, s, "", 200)
	if len(f.Records) != 1 || f.Records[0].State != "pending" {
		t.Fatal("pending finalization presented as committed", f)
	}
	after, _ := os.ReadFile(s.loadBalancePendingPath())
	if !bytes.Equal(before, after) {
		t.Fatal("feed recovered or deleted pending record")
	}
	// Only this own fixture is intentionally damaged; the production reader
	// must retain it and refuse a partial or repaired success response.
	if e := atomicWrite(s.loadBalancePendingPath(), []byte("owned-damaged-pending\n"), 0600); e != nil {
		t.Fatal(e)
	}
	lbTrafficNativeRead(t, s, "", 409)
	after, _ = os.ReadFile(s.loadBalancePendingPath())
	if string(after) != "owned-damaged-pending\n" {
		t.Fatal("unsafe pending evidence repaired")
	}
}
func TestLoadBalanceTrafficNativeWorkerSamplingAndUnsafeInventoryRemainExplicit(t *testing.T) {
	s, _, p, original := lbHistoryFixture(t)
	lbAlertNativeInstall(t, s, "1.8.4")
	s.lbHealthWorkerCheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.lbHealthWorkerError = "owned-secret-raw-error"
	f := lbTrafficNativeRead(t, s, "", 200)
	raw, _ := json.Marshal(f)
	if f.WorkerState != "error" || strings.Contains(string(raw), s.lbHealthWorkerError) {
		t.Fatal("raw error leaked or state cleared")
	}
	s.lbHealthWorkerCheckedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if lbTrafficNativeRead(t, s, "", 200).WorkerState != "stale" {
		t.Fatal("old scheduler clock called current")
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	lbTrafficNativeRead(t, s, "", 409)
	current, _ := os.ReadFile(p)
	info, _ := os.Stat(p)
	if !bytes.Equal(original, current) || info.Mode().Perm() != 0644 {
		t.Fatal("public transaction silently repaired")
	}
	if e := os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	lbAlertNativeInstall(t, s, "1.8.5")
	lbTrafficNativeRead(t, s, "", 409)
	lbAlertNativeInstall(t, s, "1.8.4")
	unknown := filepath.Join(filepath.Dir(s.loadBalancePendingPath()), "unknown-retained-file")
	if e := atomicWrite(unknown, []byte("retained"), 0600); e != nil {
		t.Fatal(e)
	}
	lbTrafficNativeRead(t, s, "", 409)
	data, _ := os.ReadFile(unknown)
	if string(data) != "retained" {
		t.Fatal("unknown history occupant removed")
	}
}
