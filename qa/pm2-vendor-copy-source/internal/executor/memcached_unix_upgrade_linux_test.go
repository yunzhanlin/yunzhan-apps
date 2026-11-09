//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMemcachedUnixUpgradeMissingStoreIsReadOnlyAndClosedContext(t *testing.T) {
	store, _, _ := memcachedUnixJournalFixture(t)
	if err := store.checkProgramUpgrade(context.Background()); err != nil {
		t.Fatal("missing independent namespace refused", err)
	}
	if _, err := os.Lstat(store.base); !os.IsNotExist(err) {
		t.Fatal("read-only upgrade preflight initialized a journal", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if store.checkProgramUpgrade(ctx) == nil || store.checkProgramUpgrade(nil) == nil {
		t.Fatal("missing namespace hid invalid/cancelled admission")
	}
}

func TestMemcachedUnixUpgradePreparedHeldUnknownAndUnsignedTerminalAlwaysRefuse(t *testing.T) {
	for _, change := range []string{"prepared", "held", "unsigned-refused", "unknown", "partial", "public-store-lock"} {
		t.Run(change, func(t *testing.T) {
			store, raw, first := memcachedUnixJournalFixture(t)
			j := memcachedUnixJournalPrepared(t, store, raw, first)
			switch change {
			case "held":
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
			case "unsigned-refused":
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				refused := first
				refused.Sequence, refused.Phase, refused.Fault = 1, "refused", "authority-unavailable"
				if err := lease.append(refused); err != nil {
					t.Fatal(err)
				}
				lease.Close()
			case "unknown":
				if err := os.WriteFile(filepath.Join(store.base, "foreign.json"), []byte("do not remove"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.WriteFile(filepath.Join(store.base, first.Operation.JobID, "event-0001.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-store-lock":
				if err := os.Chmod(filepath.Join(store.base, "store.lock"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(store.base, first.Operation.JobID, "event-0000.json"))
			if err != nil {
				t.Fatal(err)
			}
			if store.checkProgramUpgrade(context.Background()) == nil {
				t.Fatal("unfinished/unsigned/unsafe independent install became an empty old TCP queue")
			}
			after, err := os.ReadFile(filepath.Join(store.base, first.Operation.JobID, "event-0000.json"))
			if err != nil || string(before) != string(after) {
				t.Fatal("preflight rewrote original evidence", err)
			}
		})
	}
}
