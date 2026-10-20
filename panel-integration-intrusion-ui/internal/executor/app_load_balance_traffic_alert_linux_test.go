//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
func TestLoadBalanceAlertCancelledCallerDoesNotScanAfterWaitingOnConfigurationLock(t *testing.T) {
	s := wafPolicyFixture(t)
	for _, path := range []string{"/v1/load-balance-alert-events", "/v1/load-balance-traffic-alert-events"} {
		mux := http.NewServeMux()
		s.moduleAlertRoutes(mux)
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		s.mu.Lock()
		var started sync.WaitGroup
		started.Add(1)
		done := make(chan struct{})
		go func() { started.Done(); mux.ServeHTTP(w, req); close(done) }()
		started.Wait()
		cancel()
		s.mu.Unlock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled caller retained the observation lock")
		}
		if w.Body.Len() != 0 {
			t.Fatal("cancelled caller produced a successful inventory", w.Body.String())
		}
	}
}
func TestLoadBalanceTrafficNativeMaximumRecordAndByteBudgetsMeasuredWithoutCommands(t *testing.T) {
	s, tx, _, _ := lbHistoryFixture(t)
	lbAlertNativeInstall(t, s, "1.8.5")
	if e := os.Mkdir(s.loadBalanceArchiveDir(), 0700); e != nil {
		t.Fatal(e)
	}
	// These are private filesystem capacity fixtures, not generated live traffic
	// transactions, cold-cache benchmarks or a production/power-loss acceptance.
	for _, spec := range []struct {
		dir         string
		count, size int
	}{
		{filepath.Dir(s.loadBalancePendingPath()), 512, 256 << 10},
		{s.loadBalanceArchiveDir(), 2048, 128 << 10},
	} {
		for i := 0; i < spec.count; i++ {
			copy := tx
			if spec.count == 512 && i == 0 {
				copy.ID = tx.ID
			} else {
				copy.ID = core.ID()
			}
			raw, e := json.Marshal(copy)
			if e != nil || len(raw) >= spec.size {
				t.Fatal("capacity fixture cannot fit the original contract", e)
			}
			raw = append(raw, bytes.Repeat([]byte(" "), spec.size-len(raw))...)
			if e := atomicWrite(filepath.Join(spec.dir, copy.ID+".json"), raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	start := time.Now()
	f := lbTrafficNativeRead(t, s, "", 200)
	elapsed := time.Since(start)
	if !f.Available || len(f.Records) != 2560 || core.ValidateLoadBalanceTrafficFeed(f, time.Now()) != nil {
		t.Fatal("maximum full inventory was truncated or fabricated")
	}
	t.Logf("private warm filesystem fixture: 2560 records / 384 MiB, complete verified scan %s; no hard OS I/O latency claim", elapsed)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mux, response := http.NewServeMux(), httptest.NewRecorder()
	s.moduleAlertRoutes(mux)
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/v1/load-balance-traffic-alert-events", nil).WithContext(ctx))
	var bounded core.LoadBalanceTrafficFeed
	if ctx.Err() != nil || response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &bounded) != nil || len(bounded.Records) != 2560 {
		t.Fatal("production-size private warm fixture exceeded source read budget; do not claim this hardware cohort accepted", ctx.Err(), response.Code)
	}
	// Exact capacities remain strict: one additional original identity refuses
	// the entire response; no truncation, cleanup or evidence overwrite.
	tx.ID = core.ID()
	raw, _ := json.Marshal(tx)
	extra := filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json")
	if e := atomicWrite(extra, raw, 0600); e != nil {
		t.Fatal(e)
	}
	lbTrafficNativeRead(t, s, "", 409)
	if original, e := os.ReadFile(extra); e != nil || !bytes.Equal(original, raw) {
		t.Fatal("over-capacity evidence discarded", e)
	}
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
	lbAlertNativeInstall(t, s, "1.8.6")
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
