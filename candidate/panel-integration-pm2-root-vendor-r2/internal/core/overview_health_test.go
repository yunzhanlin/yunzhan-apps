package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOverviewHealthHasIndependentFourSecondDeadline(t *testing.T) {
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/overview" {
			t.Errorf("unexpected executor request %s %s", r.Method, r.URL.Path)
		}
		<-r.Context().Done()
	})
	// Do not globally reduce the executor's installation/control timeout.
	executor.Client.Timeout = 90 * time.Second
	a := &Server{Store: testStore(t), Executor: executor}
	w := httptest.NewRecorder()
	start := time.Now()
	a.overview(w, httptest.NewRequest("GET", "/api/overview", nil), identity{})
	elapsed := time.Since(start)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "context deadline exceeded") {
		t.Fatalf("stalled health read must fail, not return a healthy sample: %d %s", w.Code, w.Body.String())
	}
	if elapsed < 3900*time.Millisecond || elapsed > 7*time.Second {
		t.Fatalf("overview did not use its independent deadline: %v", elapsed)
	}
	if executor.Client.Timeout != 90*time.Second {
		t.Fatal("health polling changed other executor operations' timeout")
	}
}

func TestOverviewHealthHonorsEarlierCallerCancellation(t *testing.T) {
	a := &Server{Executor: NewExecutorClient("/does-not-exist-overview-health.sock")}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := httptest.NewRecorder()
	start := time.Now()
	a.overview(w, httptest.NewRequest("GET", "/api/overview", nil).WithContext(ctx), identity{})
	if w.Code != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("cancelled caller must promptly fail health read: %d", w.Code)
	}
}

func TestOverviewHealthSuccessfulReadRetainsActualSampleAndCounts(t *testing.T) {
	s := testStore(t)
	_, err := s.DB.Exec("INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", ID(), "health-owned", "health-owned", "health-owned.localhost", "running", Now(), Now())
	if err != nil {
		t.Fatal(err)
	}
	a := &Server{Store: s, Executor: registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"nginx_active":true,"sampled_at":"2026-10-10T00:00:00Z","cpu_percent":7.5}`))
	})}
	w := httptest.NewRecorder()
	a.overview(w, httptest.NewRequest("GET", "/api/overview", nil), identity{})
	var result struct {
		NginxActive bool           `json:"nginx_active"`
		SampledAt   string         `json:"sampled_at"`
		Counts      map[string]int `json:"counts"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || !result.NginxActive || result.SampledAt != "2026-10-10T00:00:00Z" || result.Counts["sites"] != 1 || result.Counts["running_sites"] != 1 {
		t.Fatalf("actual sample/counts lost: %d %s (%v)", w.Code, w.Body.String(), err)
	}
}
