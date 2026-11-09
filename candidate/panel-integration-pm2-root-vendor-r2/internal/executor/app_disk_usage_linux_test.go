//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDiskUsageAllocatedSparseHardlinkAndSpecialFileAccounting(t *testing.T) {
	f, site := fileFixture(t)
	p := filepath.Join(site, "public", "sparse.bin")
	file, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	const logical = int64(64 << 20)
	if err = file.Truncate(logical); err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("disk-fixture"), 0); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	allocated := info.Sys().(*syscall.Stat_t).Blocks * 512
	if err = file.Close(); err != nil || allocated >= logical {
		t.Fatal("fixture is not actually sparse", allocated, err)
	}
	if err = os.Link(p, filepath.Join(site, "public", "second.bin")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc", filepath.Join(site, "public", "outside")); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Mkfifo(filepath.Join(site, "public", "not-a-file"), 0600); err != nil {
		t.Fatal(err)
	}
	svc := New(Config{SitesDir: filepath.Dir(site)})
	out, err := svc.moduleDiskAt(context.Background(), filepath.Base(site), "")
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	if r["total_bytes"] != logical*2 || r["allocated_bytes"] != allocated || r["unique_logical_bytes"] != logical || r["files"] != 2 || r["unique_files"] != 1 || r["hardlink_entries"] != 1 || r["sparse_candidates"] != 1 || r["ignored_links"] != 1 || r["ignored_special"] != 1 || r["scan_complete"] != true {
		t.Fatal("logical size, actual allocated blocks or unique inode accounting wrong", r)
	}
	if r["filesystem_available"] != true || r["filesystem_capacity_bytes"].(uint64) == 0 || r["read_batch_size"] != 64 {
		t.Fatal("actual filesystem or bounded directory scan missing", r)
	}
	// Metadata-only scan must not consume FIFO, mutate sparse content or unlink aliases.
	if stat, err := f.public.Lstat("sparse.bin"); err != nil || stat.Size() != logical {
		t.Fatal(stat, err)
	}
}

func TestDiskUsageDeepDirectoryIsExplicitlyIncomplete(t *testing.T) {
	f, site := fileFixture(t)
	deep := strings.Repeat("d/", 130)
	if err := f.public.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "public", deep, "deep.bin"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := New(Config{SitesDir: filepath.Dir(site)}).moduleDiskAt(context.Background(), filepath.Base(site), "")
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	if r["depth_limited"] != true || r["scan_complete"] != false || r["partial"] != true || r["files"] != 0 {
		t.Fatal("deep scan silently certified complete", r)
	}
}

func TestDiskUsageCancelledBeforeOpeningSite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(Config{SitesDir: "/missing-owned-disk-fixture"}).moduleDiskAt(ctx, strings.Repeat("a", 32), "")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan attempted site filesystem access", err)
	}
}

func TestDiskUsageLargestFilesHaveStableEqualSizeOrder(t *testing.T) {
	_, site := fileFixture(t)
	for n := 139; n >= 0; n-- {
		if err := os.WriteFile(filepath.Join(site, "public", fmt.Sprintf("same-%03d.bin", n)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := New(Config{SitesDir: filepath.Dir(site)}).moduleDiskAt(context.Background(), filepath.Base(site), "")
	if err != nil {
		t.Fatal(err)
	}
	rows := out.(map[string]any)["largest_files"].([]map[string]any)
	if len(rows) != 100 {
		t.Fatal(len(rows))
	}
	for i, row := range rows {
		if row["path"] != fmt.Sprintf("same-%03d.bin", i) {
			t.Fatal("same-size rankings depend on directory insertion order", i, row)
		}
	}
}

func TestDiskUsageReplacedDirectoryAndPublicSymlinkAreRefused(t *testing.T) {
	_, site := fileFixture(t)
	public := filepath.Join(site, "public")
	if err := os.Mkdir(filepath.Join(public, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(public)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var expected unix.Stat_t
	if err = unix.Fstatat(int(parent.Fd()), "child", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(public, "child"), filepath.Join(public, "retained")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), filepath.Join(public, "child")); err != nil {
		t.Fatal(err)
	}
	if f, err := diskUsageOpenDir(parent, "child", &expected); err == nil {
		f.Close()
		t.Fatal("directory replacement followed link")
	}
	if err = os.Remove(filepath.Join(public, "child")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(public, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if f, err := diskUsageOpenDir(parent, "child", &expected); err == nil {
		f.Close()
		t.Fatal("different directory inode adopted")
	}
	if err = os.Rename(public, filepath.Join(site, "original-public")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(site, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("private", public); err != nil {
		t.Fatal(err)
	}
	if _, err = New(Config{SitesDir: filepath.Dir(site)}).moduleDiskAt(context.Background(), filepath.Base(site), ""); err == nil {
		t.Fatal("public symlink accepted even within site root")
	}
}

func TestDiskUsageUnknownFilesystemDoesNotBecomeZeroCapacity(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	out := map[string]any{}
	diskUsageFilesystem(f, out)
	if out["filesystem_available"] != false || out["filesystem_inodes_available"] != false || out["filesystem_error"] == nil {
		t.Fatal(out)
	}
	if _, exists := out["filesystem_capacity_bytes"]; exists {
		t.Fatal("unavailable capacity fabricated", out)
	}
}

func TestDiskUsageMetadataOverflowRefusesWithoutWrapping(t *testing.T) {
	// Synthetic stat/accumulator limits, not a physical exabyte-file claim.
	for _, st := range []unix.Stat_t{{Size: math.MaxInt64, Blocks: 0}, {Size: 1, Blocks: math.MaxInt64}, {Size: 1, Blocks: -1}} {
		w := diskUsageScan{logical: 1}
		if err := w.file("owned.bin", "", st); err == nil || w.logical != 1 || w.files != 0 {
			t.Fatal("overflow or invalid blocks accepted", w, err)
		}
	}
}

func TestDiskUsageEntryLimitStopsBeforeReadingMoreMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.bin"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Synthetic boundary state plus real incremental directory reader. This is
	// not full100000-file timing, memory high-water or filesystem-matrix proof.
	w := diskUsageScan{ctx: context.Background(), entries: diskUsageEntriesMax}
	if err = w.walk(f, "", "", 0); err != nil || !w.entryLimited || w.entries != diskUsageEntriesMax || w.files != 0 {
		t.Fatal(w, err)
	}
}

func TestDiskUsageInvalidUTF8NamesAreNotActionablePaths(t *testing.T) {
	_, site := fileFixture(t)
	if err := os.WriteFile(filepath.Join(site, "public", string([]byte{'a', 255, '.', 'b'})), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := New(Config{SitesDir: filepath.Dir(site)}).moduleDiskAt(context.Background(), filepath.Base(site), "")
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	if r["total_bytes"] != int64(3) || r["scan_complete"] != true || r["classification_limited"] != true || r["partial"] != true {
		t.Fatal(r)
	}
	rows := r["largest_files"].([]map[string]any)
	if len(rows) != 1 || rows[0]["can_drill"] != false {
		t.Fatal(rows)
	}
}

func TestDiskUsageFullEntryLimitAndRetainedBounds(t *testing.T) {
	_, site := fileFixture(t)
	public := filepath.Join(site, "public")
	var capacity syscall.Statfs_t
	if err := syscall.Statfs(public, &capacity); err != nil {
		t.Fatal(err)
	}
	// Do not deliberately fill a test host. The test fails rather than skips if
	// this private fixture cannot safely be created; no installed tree is used.
	if capacity.Bsize <= 0 || capacity.Bavail < uint64((128<<20)/capacity.Bsize) || capacity.Ffree < diskUsageEntriesMax+4096 {
		t.Fatal("insufficient free blocks or inodes for bounded private fixture")
	}
	for n := 0; n < diskUsageEntriesMax+3; n++ {
		file, err := os.OpenFile(filepath.Join(public, fmt.Sprintf("entry-%06d.bin", n)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(n, err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	fdBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	out, err := New(Config{SitesDir: filepath.Dir(site)}).moduleDiskAt(context.Background(), filepath.Base(site), "")
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	if r["entries_scanned"] != diskUsageEntriesMax || r["files"] != diskUsageEntriesMax-1 || r["unique_files"] != diskUsageEntriesMax-1 || r["entry_limited"] != true || r["scan_complete"] != false || r["partial"] != true || r["total_bytes"] != int64(0) || r["allocated_bytes"] != int64(0) {
		t.Fatal("real full-limit scan is unbounded or misreported", r["entries_scanned"], r["files"], r["scan_complete"], r["allocated_bytes"])
	}
	if len(r["largest_files"].([]map[string]any)) != 100 || len(r["directories"].(map[string]int64)) != 1 || len(r["children"].(map[string]int64)) > 1000 || r["classification_limited"] != true {
		t.Fatal("retained response collections exceeded their declared bounds")
	}
	fdAfter, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(fdAfter) > len(fdBefore) {
		t.Fatal("scan leaked directory descriptors", len(fdBefore), len(fdAfter), err)
	}
	var usage syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual private fixture files=%d visited_entries=%v returned_top=%d scan_elapsed=%s process_maxrss_kib=%d (whole test-process high-water, not scan-exclusive)", diskUsageEntriesMax+3, r["entries_scanned"], len(r["largest_files"].([]map[string]any)), elapsed, usage.Maxrss)
}
