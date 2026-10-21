//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func intrusionAdmissionReader(t *testing.T) (*hardeningFixture, *os.File) {
	t.Helper()
	f := newHardeningFixture(t)
	writer, err := f.s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	reader, err := f.s.intrusionObservationLock()
	if err != nil || reader == nil {
		t.Fatal("existing observation unavailable", err)
	}
	t.Cleanup(func() { reader.Close() })
	return f, reader
}

func TestIntrusionLockAdmissionOriginalTryLockConfusesReaderWithWriter(t *testing.T) {
	f, _ := intrusionAdmissionReader(t)
	if lock, err := f.s.intrusionMutationLock(); err == nil {
		lock.Close()
		t.Fatal("original nonblocking primitive unexpectedly admitted a reader")
	}
	if f.writes != 0 {
		t.Fatal("admission performed system operations")
	}
}

func TestIntrusionLockAdmissionWaitsOnlyForObservationBeforeAnyTransaction(t *testing.T) {
	f, reader := intrusionAdmissionReader(t)
	before := intrusionUpgradeInventory(t, f.s.Config.SystemRoot)
	type result struct {
		lock *os.File
		err  error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		lock, err := f.s.intrusionMutationLockContext(ctx)
		done <- result{lock, err}
	}()
	select {
	case got := <-done:
		if got.lock != nil {
			got.lock.Close()
		}
		t.Fatal("writer did not wait for read-only observation", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if f.writes != 0 || !reflect.DeepEqual(before, intrusionUpgradeInventory(t, f.s.Config.SystemRoot)) {
		t.Fatal("waiting created a plan, changed files or called the system")
	}
	reader.Close()
	got := <-done
	if got.err != nil || got.lock == nil {
		t.Fatal("same original request did not acquire after reader closed", got.err)
	}
	defer got.lock.Close()
	if err := f.s.intrusionJournalRequireLock(got.lock); err != nil {
		t.Fatal("admitted lock lost actual named exclusive authority", err)
	}
	if _, _, err := f.s.intrusionJournalPending(); !os.IsNotExist(err) || f.writes != 0 {
		t.Fatal("admission itself created a transaction or performed writes", err)
	}
}

func TestIntrusionLockAdmissionNeverWaitsForAnActiveWriter(t *testing.T) {
	f := newHardeningFixture(t)
	held, err := f.s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if lock, err := f.s.intrusionMutationLockContext(ctx); err == nil {
		lock.Close()
		t.Fatal("another writer admitted")
	} else if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("request waited behind another writer", err)
	}
}

func TestIntrusionLockAdmissionCancellationDoesNotCreateOrRepairAuthority(t *testing.T) {
	for _, kind := range []string{"before-open", "held-reader"} {
		t.Run(kind, func(t *testing.T) {
			var f *hardeningFixture
			if kind == "held-reader" {
				f, _ = intrusionAdmissionReader(t)
			} else {
				f = newHardeningFixture(t)
			}
			before := intrusionUpgradeInventory(t, f.s.Config.SystemRoot)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			want := context.DeadlineExceeded
			if kind == "before-open" {
				cancel()
				want = context.Canceled
			}
			if lock, err := f.s.intrusionMutationLockContext(ctx); !errors.Is(err, want) {
				if lock != nil {
					lock.Close()
				}
				t.Fatal("original cancellation was ignored", err)
			}
			if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, f.s.Config.SystemRoot)) || f.writes != 0 {
				t.Fatal("cancelled admission changed authority or system state")
			}
		})
	}
}

func TestIntrusionLockAdmissionRevalidatesNamedLockAndParentWhileWaiting(t *testing.T) {
	for _, kind := range []string{"replacement", "permissions", "parent"} {
		t.Run(kind, func(t *testing.T) {
			f, reader := intrusionAdmissionReader(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				lock, err := f.s.intrusionMutationLockContext(ctx)
				if lock != nil {
					lock.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatal("did not wait for original reader", err)
			case <-time.After(100 * time.Millisecond):
			}
			name := filepath.Join(f.s.Config.SecurityDir, intrusionMutationLockName)
			var err error
			switch kind {
			case "replacement":
				err = atomicWrite(name, []byte("external replacement\n"), 0600)
			case "permissions":
				err = os.Chmod(name, 0644)
			case "parent":
				err = os.Rename(f.s.Config.SecurityDir, f.s.Config.SecurityDir+"-original")
				if err == nil {
					err = os.Mkdir(f.s.Config.SecurityDir, 0700)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			reader.Close()
			if err := <-done; err == nil || ctx.Err() != nil {
				t.Fatal("changed identity was accepted or waited until cancellation", err)
			}
			if _, err := os.Lstat(filepath.Join(f.s.Config.SecurityDir, intrusionPendingName)); !os.IsNotExist(err) || f.writes != 0 {
				t.Fatal("refused identity created a replacement transaction", err)
			}
		})
	}
}
