//go:build linux

package diskjob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func admissionIdleFiles(t *testing.T, tree jobTree, id string) map[string]string {
	t.Helper()
	root := filepath.Join(tree.name, id)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = hashBytes(data)
	}
	return result
}

func TestHostNativeAdmissionWaitObservesBothOriginalLeasesWithoutWriting(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, _, _, _ := receiptFixture()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	launch, err := j.LaunchLease()
	if err != nil {
		t.Fatal(err)
	}
	defer launch.Close()
	run, err := j.Lease()
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	before := admissionIdleFiles(t, tree, in.JobID)
	first := time.AfterFunc(80*time.Millisecond, func() { _ = launch.Close() })
	defer first.Stop()
	last := time.AfterFunc(180*time.Millisecond, func() { _ = run.Close() })
	defer last.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var calls atomic.Int32
	started := time.Now()
	if err := j.WaitForAdmissionIdle(ctx, func() bool { calls.Add(1); return true }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 3 || time.Since(started) < 150*time.Millisecond {
		t.Fatal("one original lease was still held when the wait completed")
	}
	if !reflect.DeepEqual(before, admissionIdleFiles(t, tree, in.JobID)) || j.AdmissionBlocked() {
		t.Fatal("read-only wait wrote or sealed original evidence")
	}
	closure, err := j.SealClosure(in)
	if err != nil || closure.Kind != "admission_closed" || closure.State != "canceled" || closure.Started != nil {
		t.Fatal("one subsequent closure failed or invented a native result", closure, err)
	}
}

func TestHostNativeAdmissionWaitDeadlineAndRevocationNeverCloseOrUnlockOriginal(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "revoked"}[revoked], func(t *testing.T) {
			tree := nativeJournalFixture(t)
			in, _, _, _ := receiptFixture()
			j, _, err := publishRootRequest(tree, in)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			launch, err := j.LaunchLease()
			if err != nil {
				t.Fatal(err)
			}
			defer launch.Close()
			before := admissionIdleFiles(t, tree, in.JobID)
			ctx, cancel := context.WithTimeout(context.Background(), 130*time.Millisecond)
			defer cancel()
			calls := 0
			err = j.WaitForAdmissionIdle(ctx, func() bool { calls++; return !revoked || calls < 2 })
			if revoked && !errors.Is(err, ErrJournal) || !revoked && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline or current authority fence was ignored", err)
			}
			if !reflect.DeepEqual(before, admissionIdleFiles(t, tree, in.JobID)) || j.AdmissionBlocked() {
				t.Fatal("failed wait altered original evidence")
			}
			if lease, err := j.LaunchLease(); err == nil {
				lease.Close()
				t.Fatal("failed wait released somebody else's original lease")
			}
		})
	}
}

func TestHostNativeAdmissionWaitRefusesUnsafeLeaseAndNeverCreatesMissingLocks(t *testing.T) {
	tree := nativeJournalFixture(t)
	in, _, _, _ := receiptFixture()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	before := admissionIdleFiles(t, tree, in.JobID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := j.WaitForAdmissionIdle(ctx, func() bool { return true }); err != nil || !reflect.DeepEqual(before, admissionIdleFiles(t, tree, in.JobID)) {
		t.Fatal("wait created a missing original lease", err)
	}
	if err := j.root.WriteFile("run.lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.root.Chmod("run.lock", 0640); err != nil {
		t.Fatal(err)
	}
	if err := j.WaitForAdmissionIdle(ctx, func() bool { return true }); err == nil {
		t.Fatal("unsafe original lease became an idle admission")
	}
	info, err := j.root.Lstat("run.lock")
	if err != nil || info.Mode().Perm() != 0640 || j.AdmissionBlocked() {
		t.Fatal("unsafe original evidence was repaired or sealed", err)
	}
}
