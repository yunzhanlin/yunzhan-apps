//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMemcachedUpgradeRootMissingEmptyAndInterruptedStoresAreReadonly(t *testing.T) {
	for _, scenario := range []string{"absent", "empty", "missing-lock", "public-lock", "symlink-lock", "held-lock", "unknown-member", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			base, _ := memcachedPlanFileFixture(t)
			store := memcachedUpdateJournalStore{base: filepath.Join(filepath.Dir(base), "journals")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario != "absent" {
				d, err := geoJobDirectory(store.base, true)
				if err != nil {
					t.Fatal(err)
				}
				defer d.Close()
				if scenario != "missing-lock" {
					lock, err := geoStoreLock(d.Root)
					if err != nil {
						t.Fatal(err)
					}
					if scenario == "held-lock" {
						defer lock.Close()
					} else {
						lock.Close()
					}
				}
				switch scenario {
				case "public-lock":
					if err := os.Chmod(filepath.Join(store.base, "store.lock"), 0644); err != nil {
						t.Fatal(err)
					}
				case "symlink-lock":
					if err := os.Rename(filepath.Join(store.base, "store.lock"), filepath.Join(store.base, "original.lock")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("original.lock", filepath.Join(store.base, "store.lock")); err != nil {
						t.Fatal(err)
					}
				case "unknown-member":
					if err := os.WriteFile(filepath.Join(store.base, "unknown.json"), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				}
			}
			before, beforeErr := os.ReadDir(store.base)
			original := map[string]os.FileInfo{}
			for _, entry := range before {
				info, err := os.Lstat(filepath.Join(store.base, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				original[entry.Name()] = info
			}
			err := store.checkProgramUpgrade(ctx)
			allow := scenario == "absent" || scenario == "empty"
			if (err == nil) != allow {
				t.Fatalf("allow=%v: %v", allow, err)
			}
			after, afterErr := os.ReadDir(store.base)
			if os.IsNotExist(beforeErr) != os.IsNotExist(afterErr) || len(before) != len(after) {
				t.Fatal("guard created/repaired a directory, lock or member")
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("guard replaced members")
				}
				info, err := os.Lstat(filepath.Join(store.base, before[i].Name()))
				if err != nil || !geoStoreStableInfo(original[before[i].Name()], info) {
					t.Fatal("guard repaired permissions, inode or bytes", err)
				}
			}
		})
	}
}

func TestMemcachedUpgradeRootOriginalJournalAndUnsignedTerminalCannotClaimDrain(t *testing.T) {
	for _, scenario := range []string{"prepared", "pull_started", "held-run-lease", "unsigned-failed-safe", "missing-event"} {
		t.Run(scenario, func(t *testing.T) {
			store, seed := memcachedJournalFixture(t)
			j := memcachedJournalPrepare(t, store, seed)
			if scenario == "pull_started" || scenario == "unsigned-failed-safe" || scenario == "held-run-lease" {
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "held-run-lease" {
					defer lease.Close()
				} else {
					phase := "pull_started"
					if scenario == "unsigned-failed-safe" {
						phase = "failed_safe"
					}
					if err := lease.append(memcachedJournalNext(t, seed.Record, phase)); err != nil {
						t.Fatal(err)
					}
					lease.Close()
				}
			}
			if scenario == "missing-event" {
				if err := os.Rename(filepath.Join(store.base, seed.Record.Dispatch.JobID, "event-0000.json"), filepath.Join(store.base, seed.Record.Dispatch.JobID, "interrupted-event.json")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(filepath.Join(store.base, seed.Record.Dispatch.JobID))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.checkProgramUpgrade(context.Background()); err == nil {
				t.Fatal("unverified original transaction became a drain proof")
			}
			after, err := os.ReadDir(filepath.Join(store.base, seed.Record.Dispatch.JobID))
			if err != nil || len(before) != len(after) {
				t.Fatal("guard changed original journal", err)
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("guard repaired or replaced original evidence")
				}
			}
		})
	}
}
