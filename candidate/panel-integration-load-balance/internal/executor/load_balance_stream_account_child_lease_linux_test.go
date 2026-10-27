//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Real kernel descriptors and FLOCKs on a trusted private fixture. The child
// adapter must coordinate with the normal original owner without requiring
// a writable ledger, initializing a missing lock or changing its identity.
func TestLoadBalanceStreamAccountChildComposeExistingReadOnlyExclusiveLease(t *testing.T) {
	fixture := dockerMutationFixture(t)
	store := loadBalanceStreamAccountComposeStore()
	store.state, store.blocked = fixture.state, fixture.blocked
	lock := filepath.Join(store.state, "docker-jobs", "compose.lock")
	if lease, err := store.acquire(t.Context()); err == nil {
		lease.Close()
		t.Fatal("account child initialized a missing original Compose lock")
	}
	if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing original lock was created", err)
	}
	original, err := fixture.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	original.Close()
	before, err := os.Lstat(lock)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.acquire(t.Context())
	if err != nil {
		t.Fatal("existing read-only child coordination refused", err)
	}
	defer lease.Close()
	for _, held := range lease.files {
		flags, err := unix.FcntlInt(held.file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("child lease needs a write-opening descriptor", err)
		}
	}
	other, err := os.OpenFile(lock, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("read-only child failed to exclude the normal original writer", err)
	}
	lease.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("closed child failed to release its original lock", err)
	}
	if after, err := os.Lstat(lock); err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("child changed the original lock", err)
	}
	called := false
	if lease.use(context.Background(), func(context.Context) error { called = true; return nil }) == nil || called {
		t.Fatal("closed child lease retained authority")
	}
}
