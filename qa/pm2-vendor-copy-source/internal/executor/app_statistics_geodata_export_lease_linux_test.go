//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func TestStatisticsGeoJobExportSharesBackgroundReadButNotLifecycleWriteLease(t *testing.T) {
	store, id, original, _ := geoArchiveRootFixture(t)
	lockPath := filepath.Join(filepath.Dir(store.active), "instance.lock")
	reader, err := statisticsGeoInstanceLeaseAt(lockPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	// Deterministically reproduce the old exclusive-export conflict while a
	// legitimate background verifier holds its shared instance lease.
	if old, e := statisticsGeoInstanceLeaseAt(lockPath, true); e == nil {
		old.Close()
		t.Fatal("exclusive lifecycle lease overlapped reader")
	}
	before := programQueueTree(t, filepath.Dir(store.active))
	out, err := store.exportJobWithInstanceLease(context.Background(), core.StatisticsGeoExportInput{JobID: id, SHA: original.SHA}, lockPath)
	if err != nil || out.Record.JobID != id || out.Record.SHA != original.SHA || out.BundleSHA == "" {
		t.Fatal("readonly export blocked by another reader", out, err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, filepath.Dir(store.active))) {
		t.Fatal("export changed original job or instance lock")
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := statisticsGeoInstanceLeaseAt(lockPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	before = programQueueTree(t, filepath.Dir(store.active))
	if _, err = store.exportJobWithInstanceLease(context.Background(), core.StatisticsGeoExportInput{JobID: id, SHA: original.SHA}, lockPath); err == nil {
		t.Fatal("export bypassed exclusive lifecycle/archive lease")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, filepath.Dir(store.active))) {
		t.Fatal("refused export changed original evidence")
	}
}

func TestStatisticsGeoJobExportNeverCreatesOrRepairsAnUntrustedInstanceLock(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "hardlink", "foreign", "mode", "nonempty"} {
		t.Run(kind, func(t *testing.T) {
			store, id, original, _ := geoArchiveRootFixture(t)
			lockPath := filepath.Join(filepath.Dir(store.active), "instance.lock")
			if kind != "missing" {
				if err := os.WriteFile(lockPath, []byte{}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "symlink":
				if err := os.Rename(lockPath, lockPath+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(lockPath+".original", lockPath); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(lockPath, lockPath+".linked"); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(lockPath, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(lockPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "nonempty":
				if err := os.WriteFile(lockPath, []byte("unexpected"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, filepath.Dir(store.active))
			if _, err := store.exportJobWithInstanceLease(context.Background(), core.StatisticsGeoExportInput{JobID: id, SHA: original.SHA}, lockPath); err == nil {
				t.Fatal("missing/unsafe instance adopted", kind)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, filepath.Dir(store.active))) {
				t.Fatal("missing/unsafe instance created or repaired", kind)
			}
		})
	}
}
