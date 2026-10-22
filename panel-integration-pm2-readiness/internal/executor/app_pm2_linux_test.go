//go:build linux

package executor

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestPM2LimitsAndActualPortReadiness(t *testing.T) {
	for _, v := range [][2]int{{0, 0}, {8, 128}, {1, 1024}} {
		if _, _, err := pm2Limits(v[0], v[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range [][2]int{{-1, 256}, {9, 64}, {8, 256}, {1, 63}, {1, 1025}} {
		if _, _, err := pm2Limits(v[0], v[1]); err == nil {
			t.Fatal("unsafe limits accepted", v)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	s := New(Config{Run: func(context.Context, string, ...string) (string, error) { return "active\n", nil }})
	if err = s.pm2Ready(context.Background(), "panel-pm2@qa-test", n); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.pm2Ready(ctx, "panel-pm2@qa-test", 1); err == nil {
		t.Fatal("cancelled or unavailable application accepted")
	}
}

func TestPM2ReadinessColdStartBudgetAndParentCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	called := false
	s := New(Config{Run: func(ctx context.Context, command string, args ...string) (string, error) {
		called = true
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 30*time.Second || remaining > 45*time.Second {
			t.Fatalf("cold startup must have a bounded 45-second budget, got %v", remaining)
		}
		return "active\n", nil
	}})
	if err = s.pm2Ready(context.Background(), "panel-pm2@qa-cold-start", n); err != nil || !called {
		t.Fatal("real port readiness with cold-start budget", err, called)
	}
	if pm2ReadinessTimeout != 45*time.Second {
		t.Fatal("startup must leave room for rollback within Core's 75-second deadline")
	}

	// A short caller deadline wins; no readiness success on supervisor state
	// alone, no automatic extension and no 45-second wait after cancellation.
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	s = New(Config{Run: func(probe context.Context, command string, args ...string) (string, error) {
		caller, _ := ctx.Deadline()
		deadline, ok := probe.Deadline()
		if !ok || !deadline.Equal(caller) {
			t.Fatal("readiness extended the caller deadline")
		}
		return "active\n", nil
	}})
	started := time.Now()
	if err = s.pm2Ready(ctx, "panel-pm2@qa-cancelled-start", 0); err == nil {
		t.Fatal("supervisor without a ready port accepted")
	}
	if ctx.Err() != context.DeadlineExceeded || time.Since(started) > 2*time.Second {
		t.Fatal("parent cancellation was not promptly honored", ctx.Err(), time.Since(started))
	}
}
