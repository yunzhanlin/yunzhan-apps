//go:build linux

package executor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestSoftwareStatusReturnsVerifiedRowsBesideBlockedNativeCheck(t *testing.T) {
	ids := []string{"nginx-waf", "disk-analysis", "platform-ops", "load-balance"}
	slots := make(chan struct{}, 2)
	var active, peak atomic.Int32
	release := make(chan struct{})
	defer close(release)
	probe := func(ctx context.Context, id string) core.SoftwareAppStatus {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		if id == "nginx-waf" {
			<-release // The total deadline remains enforced even if this probe stalls.
		}
		if id == "load-balance" {
			<-ctx.Done()
		}
		return core.SoftwareAppStatus{ID: id, Installed: true, Healthy: true, Version: "1.4.1"}
	}
	start := time.Now()
	result := collectSoftwareStatus(context.Background(), ids, 450*time.Millisecond, 200*time.Millisecond, slots, probe)
	if time.Since(start) > 2*time.Second || len(result) != len(ids) || peak.Load() > 2 {
		t.Fatalf("unbounded or incomplete collection: %v", result)
	}
	for i, row := range result {
		if row.ID != ids[i] {
			t.Fatalf("unstable order: %v", result)
		}
		if i == 0 || i == 3 {
			if !row.StateUnknown || row.Installed || row.Healthy {
				t.Fatalf("timeout was interpreted as verified: %v", row)
			}
		} else if row.StateUnknown || !row.Installed || !row.Healthy || row.Version != "1.4.1" {
			t.Fatalf("verified software lost: %v", row)
		}
	}
}

func TestSoftwareStatusRejectsDifferentIDAndPreservesAuthoritativeNotInstalled(t *testing.T) {
	result := collectSoftwareStatus(context.Background(), []string{"disk-analysis", "platform-ops"}, time.Second, time.Second,
		make(chan struct{}, 2), func(_ context.Context, id string) core.SoftwareAppStatus {
			if id == "disk-analysis" {
				return core.SoftwareAppStatus{ID: "unexpected", Installed: true}
			}
			return core.SoftwareAppStatus{ID: id, Detail: "未安装"}
		})
	if !result[0].StateUnknown || result[0].Installed || result[1].StateUnknown || result[1].Installed {
		t.Fatal(result)
	}
}
