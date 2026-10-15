//go:build linux

package diskusage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func nativeLedgerAt(t *testing.T, base string, pages int64) (*Ledger, *os.Root) {
	t.Helper()
	r, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLedger(context.Background(), r, pages)
	if err != nil {
		r.Close()
		t.Fatalf("native private bounded index unavailable: %v", err)
	}
	t.Cleanup(func() { l.Close(); r.Close() })
	return l, r
}

func TestHostLedgerNativeFreshPrivateIndexAndMetadataChanges(t *testing.T) {
	base := nativeHostFixture(t)
	l, r := nativeLedgerAt(t, base, 64)
	m := Metadata{Identity: Identity{MountID: 1, Major: 8, Minor: 2, Inode: 200}, Mode: unix.S_IFREG | 0600, Bytes: 1024, Blocks: 2, Links: 1}
	if fresh, err := l.Add(context.Background(), m); err != nil || !fresh {
		t.Fatal("new native index identity refused", err)
	}
	if fresh, err := l.Add(context.Background(), m); err != nil || fresh {
		t.Fatal("hardlink identity incorrectly counted twice", err)
	}
	m.Bytes++
	if fresh, err := l.Add(context.Background(), m); !errors.Is(err, ErrMetadataChanged) || fresh {
		t.Fatal("changed inode silently deduplicated", err)
	}
	if err := l.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if l.db.QueryRow(`SELECT count(*) FROM inodes`).Scan(&count) != nil || count != 1 {
		t.Fatal("native index lost original immutable identity")
	}
	if other, err := NewLedger(context.Background(), r, 64); !errors.Is(err, ErrLedgerUnavailable) {
		if other != nil {
			other.Close()
		}
		t.Fatal("existing index overwritten or implicitly reopened")
	}
	for _, pages := range []int64{0, 15, 131073, math.MaxInt64} {
		if _, err := NewLedger(context.Background(), r, pages); !errors.Is(err, ErrLedgerUnavailable) {
			t.Fatal("invalid index quota accepted")
		}
	}
	if l.Close() != nil || l.Close() != nil {
		t.Fatal("index close not idempotent")
	}
	if _, err := l.Add(context.Background(), m); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatal("closed private index reused")
	}
}

func TestHostLedgerNativeRefusesUnsafeOwnershipAndReplacedParent(t *testing.T) {
	base := nativeHostFixture(t)
	public := filepath.Join(base, "public-mode")
	if os.Mkdir(public, 0755) != nil {
		t.Fatal("owned unsafe-permission fixture failed")
	}
	r, err := os.OpenRoot(public)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := NewLedger(context.Background(), r, 64); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatal("public index root accepted")
	}
	info, _ := os.Lstat(public)
	if info.Mode().Perm() != 0755 {
		t.Fatal("unsafe existing root repaired instead of refused")
	}
	child := filepath.Join(base, "foreign-owner")
	if os.Mkdir(child, 0700) != nil || os.Chown(child, 65534, 65534) != nil {
		t.Fatal("ordinary foreign-UID fixture failed")
	}
	foreign, err := os.OpenRoot(child)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if _, err := NewLedger(context.Background(), foreign, 64); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatal("another account's private directory accepted")
	}
	good := filepath.Join(base, "bound-private")
	if os.Mkdir(good, 0700) != nil {
		t.Fatal("owned parent fixture failed")
	}
	l, _ := nativeLedgerAt(t, good, 64)
	m := Metadata{Identity: Identity{MountID: 1, Major: 8, Minor: 2, Inode: 20}, Mode: unix.S_IFREG, Bytes: 1, Blocks: 1}
	if _, err := l.Add(context.Background(), m); err != nil || l.Flush(context.Background()) != nil {
		t.Fatal("native index prerequisite failed", err)
	}
	if os.Rename(good, good+"-retained-original") != nil || os.Mkdir(good, 0700) != nil {
		t.Fatal("owned parent substitution fixture failed")
	}
	m.Identity.Inode++
	if _, err := l.Add(context.Background(), m); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatal("substituted parent accepted as current private state")
	}
	if _, err := os.Lstat(filepath.Join(good, "inode-index.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement directory received index writes")
	}
}

func TestHostLedgerNativePageBudgetRetainsOriginalSpool(t *testing.T) {
	base := nativeHostFixture(t)
	l, _ := nativeLedgerAt(t, base, 16)
	failed := false
	for n := uint64(1); n <= 4000; n++ {
		m := Metadata{Identity: Identity{MountID: 1, Major: 8, Minor: 2, Inode: n}, Mode: unix.S_IFREG, Bytes: math.MaxUint64, Blocks: 2}
		_, err := l.Add(context.Background(), m)
		if err != nil {
			if !errors.Is(err, ErrLedgerUnavailable) {
				t.Fatal(err)
			}
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("native SQLite page quota did not stop index growth")
	}
	if l.Close() != nil {
		t.Fatal("quota failure index close failed")
	}
	info, err := os.Lstat(filepath.Join(base, "inode-index.db"))
	if err != nil || info.Size() > 16*4096 || info.Size() < 4096 || !ledgerPrivateInfo(info, false) {
		t.Fatal("original quota-bounded private index missing, oversized, or repaired")
	}
}

func independentNativeUsage(t *testing.T, base string) (ScanReport, map[string]unix.Stat_t) {
	t.Helper()
	r := ScanReport{}
	seen := map[[2]uint64]bool{}
	regular := map[string]unix.Stat_t{}
	err := filepath.WalkDir(base, func(p string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		var s unix.Stat_t
		if err := unix.Lstat(p, &s); err != nil {
			return err
		}
		if p != base {
			r.EntriesRead++
		}
		key := [2]uint64{uint64(s.Dev), s.Ino}
		fresh := !seen[key]
		seen[key] = true
		a := uint64(s.Blocks) * 512
		switch s.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			regular[p] = s
			r.Files++
			r.LogicalBytes += uint64(s.Size)
			if fresh {
				r.UniqueFiles++
				r.UniqueLogicalBytes += uint64(s.Size)
				r.FileAllocatedBytes += a
				if a < uint64(s.Size) {
					r.Sparse++
				}
			} else {
				r.Hardlinks++
			}
		case unix.S_IFDIR:
			r.Directories++
			if fresh {
				r.DirectoryAllocatedBytes += a
			}
		case unix.S_IFLNK:
			r.Links++
			if fresh {
				r.LinkAllocatedBytes += a
			}
		default:
			r.Special++
			if fresh {
				r.SpecialAllocatedBytes += a
			}
		}
		if fresh {
			r.AllocatedBytes += a
		}
		return nil
	})
	if err != nil {
		t.Fatal("independent native metadata fixture failed", err)
	}
	return r, regular
}

func TestHostScanNativeWholeSelectedSubtreeAccountingAndNoContentReads(t *testing.T) {
	base := nativeHostFixture(t)
	nested, rawDir := filepath.Join(base, "nested"), filepath.Join(base, "raw-\xff")
	if os.Mkdir(nested, 0700) != nil || os.Mkdir(rawDir, 0700) != nil {
		t.Fatal("owned scan directories failed")
	}
	p := filepath.Join(base, "sparse.bin")
	nativeWrite(t, p, []byte("source-owned-metadata"))
	if os.Truncate(p, 64<<20) != nil || os.Link(p, filepath.Join(nested, "alias.bin")) != nil || os.Chmod(p, 0) != nil || unix.UtimesNano(p, []unix.Timespec{{Sec: 1}, {Sec: 1}}) != nil {
		t.Fatal("owned sparse/hardlink prerequisites failed")
	}
	nativeWrite(t, filepath.Join(nested, "regular.txt"), []byte("known"))
	nativeWrite(t, filepath.Join(rawDir, "raw-child"), []byte("raw"))
	if os.Symlink("nested", filepath.Join(base, "link-do-not-follow")) != nil || unix.Mkfifo(filepath.Join(base, "fifo-do-not-open"), 0600) != nil {
		t.Fatal("owned non-regular prerequisites failed")
	}
	want, before := independentNativeUsage(t, base)
	i, m, relative := nativeMountFor(t, base)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l, _ := nativeLedgerAt(t, nativeHostFixture(t), 1024)
	r, err := Scan(context.Background(), s, relative, l, DefaultScanBudget())
	if err != nil || !r.Complete || r.State != "complete" || !r.IndexFlushed || r.SnapshotConsistent || r.ExclusivePhysicalBytes || len(r.Reasons) != 0 || r.MountID != m.ID || r.BindingSHA != m.BindingSHA {
		t.Fatalf("native selected subtree did not enumerate safely: %+v %v", r, err)
	}
	if r.EntriesRead != want.EntriesRead || r.Files != want.Files || r.UniqueFiles != want.UniqueFiles || r.Hardlinks != want.Hardlinks || r.Directories != want.Directories || r.Links != want.Links || r.Special != want.Special || r.LogicalBytes != want.LogicalBytes || r.UniqueLogicalBytes != want.UniqueLogicalBytes || r.FileAllocatedBytes != want.FileAllocatedBytes || r.DirectoryAllocatedBytes != want.DirectoryAllocatedBytes || r.LinkAllocatedBytes != want.LinkAllocatedBytes || r.SpecialAllocatedBytes != want.SpecialAllocatedBytes || r.AllocatedBytes != want.AllocatedBytes || r.Sparse != want.Sparse {
		t.Fatalf("native usage disagrees with independent inode metadata: got=%+v want=%+v", r, want)
	}
	_, after := independentNativeUsage(t, base)
	for name, original := range before {
		if after[name] != original {
			t.Fatal("scanner read source file content/atime or changed an original inode")
		}
	}
	if len(r.TopFiles) != int(want.Files) || len(r.TopDirectories) != int(want.Directories) {
		t.Fatal("native top rows incomplete for small owned fixture")
	}
	for _, row := range append(r.TopFiles, r.TopDirectories...) {
		if strings.Contains(row.Path, "raw-�") && row.Actionable {
			t.Fatal("invalid native filename became a GUI action path")
		}
	}
	if _, err := Scan(context.Background(), s, relative, l, DefaultScanBudget()); !errors.Is(err, ErrScanReused) {
		t.Fatal("original index implicitly replayed as a new complete scan")
	}
	encoded, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(encoded), `"regular_logical_entry_bytes":"`) || !strings.Contains(string(encoded), `"inode_allocated_bytes":"`) {
		t.Fatal("browser integer rounding introduced")
	}
}

func TestHostScanNativeLimitsOwnStateAndCancellationAreNotComplete(t *testing.T) {
	base := nativeHostFixture(t)
	if os.Mkdir(filepath.Join(base, "deep"), 0700) != nil || os.Mkdir(filepath.Join(base, "deep", "deeper"), 0700) != nil {
		t.Fatal("owned depth fixture failed")
	}
	nativeWrite(t, filepath.Join(base, "deep", "deeper", "not-reached.bin"), []byte("owned"))
	for n := range 70 {
		nativeWrite(t, filepath.Join(base, fmt.Sprintf("entry-%03d", n)), nil)
	}
	i, m, relative := nativeMountFor(t, base)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l, _ := nativeLedgerAt(t, nativeHostFixture(t), 256)
	r, err := Scan(context.Background(), s, relative, l, ScanBudget{Entries: 1, Depth: 1})
	if err != nil || r.State != "partial" || r.Complete || r.EntriesRead != 1 || !strings.Contains(strings.Join(r.Reasons, ","), "entry_budget_reached") {
		t.Fatalf("metadata entry limit became complete: %+v %v", r, err)
	}
	own := filepath.Join(base, "only-own-worker-state")
	other := filepath.Join(base, "only-own-worker-state-not-the-worker")
	if os.Mkdir(own, 0700) != nil || os.Mkdir(other, 0700) != nil {
		t.Fatal("owned exact identity exclusion fixture failed")
	}
	nativeWrite(t, filepath.Join(other, "must-count.bin"), []byte("still-source"))
	ownLedger, _ := nativeLedgerAt(t, own, 256)
	r, err = Scan(context.Background(), s, relative, ownLedger, ScanBudget{Entries: 1000, Depth: 1})
	if err != nil || r.State != "partial" || r.Complete || r.OwnWorkerDirectories != 1 || r.Files != 71 || !strings.Contains(strings.Join(r.Reasons, ","), "own_worker_state_excluded") || !strings.Contains(strings.Join(r.Reasons, ","), "depth_budget_reached") {
		t.Fatalf("own spool/prefix/depth exclusion misrepresented: %+v %v", r, err)
	}
	cancelLedger, _ := nativeLedgerAt(t, nativeHostFixture(t), 256)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = Scan(ctx, s, relative, cancelLedger, DefaultScanBudget())
	if !errors.Is(err, context.Canceled) || r.State != "canceled" || r.Complete || r.IndexFlushed || r.EntriesRead != 0 {
		t.Fatal("cancelled scan treated as successful or started enumeration")
	}
	if _, err := Scan(context.Background(), s, relative, cancelLedger, ScanBudget{Entries: 100000001, Depth: 1}); !errors.Is(err, ErrScanBudget) {
		t.Fatal("oversized enumeration budget accepted")
	}
}

func TestHostScanNativeSpoolQuotaFailureNoUnboundedFallback(t *testing.T) {
	base := nativeHostFixture(t)
	for n := range 4000 {
		nativeWrite(t, filepath.Join(base, fmt.Sprintf("entry-%04d", n)), nil)
	}
	i, m, relative := nativeMountFor(t, base)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	l, _ := nativeLedgerAt(t, nativeHostFixture(t), 16)
	r, err := Scan(context.Background(), s, relative, l, DefaultScanBudget())
	if !errors.Is(err, ErrLedgerUnavailable) || r.Complete || r.State != "failed" || r.IndexFlushed || r.EntriesRead > 4000 || len(r.TopFiles) > 100 || len(r.TopDirectories) > 100 || !strings.Contains(strings.Join(r.Reasons, ","), "index_unavailable_or_capacity_reached") {
		t.Fatalf("spool quota failure masked, complete or unbounded: %+v %v", r, err)
	}
}

func TestHostUsageRowsAndOverflowRemainBounded(t *testing.T) {
	for _, raw := range []string{"/raw-\xff", "/control\n", "/" + strings.Repeat("界", 400)} {
		display, actionable := boundedUsagePath(raw)
		if actionable || len(display) > 515 || strings.ContainsAny(display, "\n\r\t") {
			t.Fatal("unsafe/oversized path action or report escaped bounds")
		}
	}
	rows := []UsageRow{}
	for n := range 3000 {
		retainTop(&rows, UsageRow{Path: fmt.Sprintf("/row-%04d", n), AllocatedBytes: uint64(n)})
	}
	if len(rows) != 100 || rows[0].AllocatedBytes != 2999 || rows[99].AllocatedBytes != 2900 {
		t.Fatal("top rows not exact and bounded")
	}
	value := uint64(math.MaxUint64)
	if !errors.Is(addUsage(&value, 1), ErrUsageOverflow) || value != math.MaxUint64 {
		t.Fatal("usage overflow fabricated wrapped bytes")
	}
	if _, err := allocation(Metadata{Blocks: math.MaxUint64}); !errors.Is(err, ErrUsageOverflow) {
		t.Fatal("512-byte block conversion overflow accepted")
	}
}
