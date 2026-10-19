package upgradeguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPendingAndUnsafePathsBlockWithoutChangingEvidence(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "pending")
	if blockedAt(path) {
		t.Fatal("ordinary absent marker blocks")
	}
	if err := os.WriteFile(path, []byte("retained interrupted transaction\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !blockedAt(path) {
		t.Fatal("pending transaction accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "retained interrupted transaction\n" {
		t.Fatal("evidence changed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if !blockedAt(path) {
		t.Fatal("dangling marker accepted")
	}
	parent := filepath.Join(root, "linked")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	if !blockedAt(filepath.Join(parent, "absent")) {
		t.Fatal("linked parent treated as ordinary absence")
	}
}

func TestWaitStartsOnlyAfterCommitAndNeverAfterCancellation(t *testing.T) {
	var pending atomic.Bool
	pending.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- wait(ctx, pending.Load, time.Millisecond) }()
	select {
	case <-result:
		t.Fatal("writer started before commit")
	case <-time.After(10 * time.Millisecond):
	}
	pending.Store(false)
	select {
	case ready := <-result:
		if !ready {
			t.Fatal("committed worker not started")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not observe commit")
	}
	cancel()
	if wait(ctx, func() bool { return false }, time.Millisecond) {
		t.Fatal("cancelled process starts writer")
	}
	ctx, cancel = context.WithCancel(context.Background())
	pending.Store(true)
	go func() { result <- wait(ctx, pending.Load, time.Millisecond) }()
	cancel()
	if <-result {
		t.Fatal("pending interrupted process starts writer")
	}
}

func TestCandidateHTTPPermitsOnlyExactGETProbeAndMakesNoOtherRouteCalls(t *testing.T) {
	var calls atomic.Int32
	var pending atomic.Bool
	pending.Store(true)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	guard := handler(next, pending.Load, "/api/ready")
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"} {
		for _, path := range []string{"/api/ready", "/api/ready/extra", "/api/app-registry", "/api/session/activity", "/collect/analytics/event", "/"} {
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
			if method == "GET" && path == "/api/ready" {
				if recorder.Code != http.StatusNoContent {
					t.Fatal("fixed readiness probe blocked")
				}
			} else if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "3" || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("candidate route not closed", method, path, recorder.Code)
			}
		}
	}
	if calls.Load() != 1 {
		t.Fatal("blocked route changed state", calls.Load())
	}
	pending.Store(false)
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, httptest.NewRequest("POST", "/api/session/activity", nil))
	if recorder.Code != http.StatusNoContent || calls.Load() != 2 {
		t.Fatal("committed normal route unavailable")
	}
}
