//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLoadBalanceStreamControlOwnerOldOpenerOrClaimCannotSelectHostEffects(t *testing.T) {
	for _, w := range []*loadBalanceStreamControlOwner{nil, {}, {gate: &loadBalanceStreamControlGate{}}, {process: &moduleApplyOwner{PID: 219, StartTime: 1}}, {lifetime: &memcachedUnixRuntimeLease{}, mutation: &loadBalanceStreamMutationLease{}}} {
		if err := w.current(context.Background()); err != errLoadBalanceStreamInstallationGate {
			t.Fatal("old/claimed controller became original owner", err)
		}
	}
	if w, err := bindLoadBalanceStreamControlOwner(context.Background(), &loadBalanceStreamControlGate{}, &memcachedUnixRuntimeLease{}, &loadBalanceStreamMutationLease{}); err == nil || w != nil {
		t.Fatal("missing original journal/grant/leases selected process effects")
	}
	if streamControlHeldLease(nil, true) || streamControlLeaseFDInfo([]byte("lock: 1: FLOCK ADVISORY WRITE 219 0:0:1 0 EOF\n"), 219, nil, true) {
		t.Fatal("saved lock text became a kernel lease")
	}
}

func TestLoadBalanceStreamControlOwnerNativeActualOwnSharedAndExclusiveKernelLease(t *testing.T) {
	root, _, _ := streamGenerationNativeRoot(t)
	f, err := root.OpenFile("original.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Chown(0, 0); err != nil {
		t.Fatal(err)
	}
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil || !streamControlHeldLease(f, false) || streamControlHeldLease(f, true) {
		t.Fatal("actual original shared lease was not measured exactly")
	}
	other, err := root.OpenFile("original.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if streamControlHeldLease(other, false) || streamControlHeldLease(other, true) {
		t.Fatal("another descriptor adopted original process lease")
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatal("shared lease did not exclude an actual writer", err)
	}
	raw, err := streamAccountParentProc("/proc/self/fdinfo/"+strconv.FormatUint(uint64(f.Fd()), 10), 8192)
	if err != nil || !streamControlLeaseFDInfo(raw, os.Getpid(), before, false) {
		t.Fatal("actual own kernel fdinfo refused", err)
	}
	if streamControlLeaseFDInfo(raw, os.Getpid()+1, before, false) || streamControlLeaseFDInfo(raw, os.Getpid(), before, true) || streamControlLeaseFDInfo(bytes.Replace(raw, []byte("READ"), []byte("WRITE"), 1), os.Getpid(), before, false) {
		t.Fatal("changed owner/mode claims acquired original lease")
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || !streamControlHeldLease(f, true) || streamControlHeldLease(f, false) {
		t.Fatal("actual original exclusive lease was not measured exactly")
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_UN) != nil || streamControlHeldLease(f, true) || streamControlHeldLease(f, false) {
		t.Fatal("released kernel lease remained current")
	}
	after, err := f.Stat()
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("read-only lease observation changed original file metadata", err)
	}
}
