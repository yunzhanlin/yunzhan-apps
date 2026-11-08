//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeInstallTimeoutIsBoundedAndReviewed(t *testing.T) {
	for _, release := range runtimecatalog.All() {
		want := 110 * time.Minute
		if release.Family == "php" {
			want = 4 * time.Hour
		}
		got := runtimeInstallTimeout(release)
		if got != want || got <= 0 || got > 4*time.Hour {
			t.Fatalf("%s: install budget %s, want %s", release.ID, got, want)
		}
	}
}

func TestRuntimeBuildLockHasBoundedWaitAndNoBypass(t *testing.T) {
	name := filepath.Join(t.TempDir(), "build.lock")
	owner, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	waiter, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = acquireRuntimeBuildLock(ctx, waiter); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held build lock bypassed: %v", err)
	}
	if err = syscall.Flock(int(owner.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err = acquireRuntimeBuildLock(context.Background(), waiter); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(waiter.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err = acquireRuntimeBuildLock(cancelled, waiter); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lock request accepted: %v", err)
	}
	if err = waiter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = acquireRuntimeBuildLock(context.Background(), waiter); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("invalid descriptor accepted: %v", err)
	}
}
