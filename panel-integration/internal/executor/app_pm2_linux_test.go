//go:build linux

package executor

import (
	"context"
	"net"
	"strconv"
	"testing"
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
