//go:build linux

package diskusage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLedgerDatabaseFailurePreservesOnlyControlCauses(t *testing.T) {
	private := errors.New("private SQLite statement /private/worker/index.db")
	canceled, stop := context.WithCancel(context.Background())
	stop()
	expired, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer finish()
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		err, cause error
	}{
		{"ordinary-storage-failure", context.Background(), private, nil},
		{"canceled-statement", canceled, private, context.Canceled},
		{"expired-statement", expired, sql.ErrTxDone, context.DeadlineExceeded},
		{"driver-cancellation", context.Background(), context.Canceled, context.Canceled},
		{"driver-deadline", context.Background(), context.DeadlineExceeded, context.DeadlineExceeded},
		{"policy-mismatch-after-cancel", canceled, nil, nil},
		{"transaction-done-without-cancel", context.Background(), sql.ErrTxDone, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ledgerDatabaseFailure(tc.ctx, tc.err)
			if got.Error() != ErrLedgerUnavailable.Error() || !errors.Is(got, ErrLedgerUnavailable) || errors.Is(got, private) || strings.Contains(got.Error(), "private") {
				t.Fatal("private SQL details leaked or unavailable index identity lost", got)
			}
			if tc.cause != nil {
				if !errors.Is(got, tc.cause) {
					t.Fatal("original cancellation/deadline cause lost", got)
				}
			} else if errors.Is(got, context.Canceled) || errors.Is(got, context.DeadlineExceeded) {
				t.Fatal("non-control failure mislabeled by unrelated cancellation")
			}
		})
	}
}

func TestHostLedgerNativeCanceledInitializationCreatesNoIndex(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		base := nativeHostFixture(t)
		root, err := os.OpenRoot(base)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		cancel()
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		}
		ledger, err := NewLedger(ctx, root, 64)
		cancel()
		root.Close()
		if ledger != nil || !errors.Is(err, want) {
			t.Fatal("canceled initialization not refused", err)
		}
		if _, err := os.Lstat(filepath.Join(base, "inode-index.db")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("already canceled initialization created an index")
		}
	}
}

type ledgerEntryContext struct {
	context.Context
	first chan struct{}
	once  sync.Once
}

func (c *ledgerEntryContext) Err() error {
	err := c.Context.Err()
	if err == nil {
		c.once.Do(func() { close(c.first) })
	}
	return err
}

// Hold a real exclusive SQLite lock so cancellation/deadline occurs inside
// the original database operation, rather than at Scan/Add's entry check.
// Only newly owned Root fixtures are touched; the bounded spool is retained.
func TestHostLedgerNativeSQLControlCancellationRetainsOriginalIndex(t *testing.T) {
	for _, operation := range []string{"add", "scan"} {
		for _, deadline := range []bool{false, true} {
			name := operation + "-cancel"
			if deadline {
				name = operation + "-deadline"
			}
			t.Run(name, func(t *testing.T) {
				ledger, _ := nativeLedgerAt(t, nativeHostFixture(t), 64)
				locked, err := sql.Open("sqlite", "/proc/self/fd/"+strconv.FormatUint(uint64(ledger.directory.Fd()), 10)+"/inode-index.db")
				if err != nil {
					t.Fatal(err)
				}
				locked.SetMaxOpenConns(1)
				defer locked.Close()
				if _, err := locked.Exec("BEGIN EXCLUSIVE"); err != nil {
					t.Fatal(err)
				}
				defer locked.Exec("ROLLBACK")
				var scope *Scope
				var relative string
				if operation == "scan" {
					tree := nativeHostFixture(t)
					nativeWrite(t, filepath.Join(tree, "sentinel"), []byte("unchanged"))
					inv, m, r := nativeMountFor(t, tree)
					relative = r
					scope, err = inv.OpenMount(context.Background(), m.ID, m.BindingSHA)
					if err != nil {
						t.Fatal(err)
					}
					defer scope.Close()
				}
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				gated := &ledgerEntryContext{Context: ctx, first: make(chan struct{})}
				seen := make(chan bool, 1)
				go func() {
					select {
					case <-gated.first:
					case <-ctx.Done():
						seen <- false
						return
					}
					limit := time.Now().Add(2 * time.Second)
					for ledger.db.Stats().InUse == 0 {
						if time.Now().After(limit) || ctx.Err() != nil {
							seen <- false
							cancel()
							return
						}
						time.Sleep(time.Millisecond)
					}
					time.Sleep(20 * time.Millisecond)
					seen <- true
					if !deadline {
						cancel()
					}
				}()
				var report ScanReport
				if operation == "add" {
					_, err = ledger.Add(gated, Metadata{Identity: Identity{MountID: 1, Major: 8, Minor: 2, Inode: 731}, Mode: unix.S_IFREG | 0600, Bytes: 1, Blocks: 1})
				} else {
					report, err = ScanObserved(gated, scope, relative, ledger, DefaultScanBudget(), nil)
				}
				if !<-seen {
					t.Fatal("fixture never entered an original active SQL connection")
				}
				if !errors.Is(err, want) || !errors.Is(err, ErrLedgerUnavailable) {
					t.Fatal("in-flight native SQL lost its original cancellation/deadline", err)
				}
				if operation == "scan" {
					state, reason := "canceled", "canceled"
					if deadline {
						state, reason = "failed", "deadline_reached"
					}
					if report.State != state || report.Complete || report.IndexFlushed || !strings.Contains(strings.Join(report.Reasons, ","), reason) || strings.Contains(strings.Join(report.Reasons, ","), "index_unavailable_or_capacity_reached") {
						t.Fatal("interrupted original scan claimed a storage failure or completion", report.State, report.Reasons)
					}
				}
				if _, err := locked.Exec("ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := ledger.db.QueryRow("SELECT count(*) FROM inodes").Scan(&count); err != nil || count != 0 {
					t.Fatal("interrupted statement published records", count, err)
				}
				info, err := os.Lstat(filepath.Join(ledger.root.Name(), "inode-index.db"))
				if err != nil || !ledgerPrivateInfo(info, false) || info.Size() > 64*4096 {
					t.Fatal("original private bounded spool missing or changed", err)
				}
			})
		}
	}
}
