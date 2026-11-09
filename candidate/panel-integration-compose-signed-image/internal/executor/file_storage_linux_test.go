//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func storageTestCategory(id, path string) core.FileStorageCategory {
	return core.FileStorageCategory{ID: id, Label: id, Paths: []string{path}}
}

func TestStorageAllocatedBlocksLinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, p := range []string{first, second} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sparse := filepath.Join(first, "sparse")
	f, err := os.OpenFile(sparse, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(8 << 30); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("allocated"), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = os.Link(sparse, filepath.Join(first, "same")); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(sparse, filepath.Join(second, "cross-category")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err = os.WriteFile(filepath.Join(outside, "untouched"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"external": outside, "contained": "sparse", "long": strings.Repeat("missing/", 120)} {
		if err = os.Symlink(target, filepath.Join(first, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Mkfifo(filepath.Join(first, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(sparse)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := collectStorageUsage(ctx, root, []core.FileStorageCategory{storageTestCategory("first", first), storageTestCategory("second", second)}, 100, 100)
	if err != nil || !got.Complete || !got.Reconciled || got.OtherBytes == nil {
		t.Fatalf("incomplete %+v: %v", got, err)
	}
	if got.Categories[0].Deduplicated != 1 || got.Categories[1].Deduplicated != 1 {
		t.Fatalf("hardlinks counted twice: %+v", got.Categories)
	}
	// Compare an independent implementation, in the same category order.
	output, err := exec.Command("du", "-x", "-s", "-B1", first, second).Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Fatal(string(output))
	}
	for i, line := range lines {
		n, e := strconv.ParseUint(strings.Fields(line)[0], 10, 64)
		if e != nil || got.Categories[i].Bytes == nil || *got.Categories[i].Bytes != n {
			t.Fatalf("allocated blocks differ from GNU du: %+v / %s", got.Categories[i], line)
		}
	}
	if *got.Categories[0].Bytes >= 8<<30 {
		t.Fatal("sparse logical size counted as allocation")
	}
	after, err := os.Lstat(sparse)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("scan changed file")
	}
	untouched, err := os.ReadFile(filepath.Join(outside, "untouched"))
	if err != nil || string(untouched) != "original" {
		t.Fatal("external target changed")
	}
	sum := *got.Categories[0].Bytes + *got.Categories[1].Bytes + *got.OtherBytes
	if sum != got.DiskUsed {
		t.Fatal("residual does not reconcile")
	}
}

func TestStorageLimitsCancellationAndUnavailable(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, limit := range []struct {
		name            string
		total, category int
	}{{"global", 2, 100}, {"category", 100, 2}} {
		t.Run(limit.name, func(t *testing.T) {
			got, err := collectStorageUsage(context.Background(), root, []core.FileStorageCategory{storageTestCategory("data", dir)}, limit.total, limit.category)
			if err != nil || got.Complete || got.Reconciled || got.OtherBytes != nil || got.Scanned != 2 || got.Categories[0].State != "partial" || got.Categories[0].Bytes == nil {
				t.Fatalf("limit hidden: %+v %v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collectStorageUsage(ctx, root, nil, 100, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	got, err := collectStorageUsage(context.Background(), root, []core.FileStorageCategory{storageTestCategory("unknown", link), storageTestCategory("missing", filepath.Join(root, "missing"))}, 100, 100)
	if err != nil || got.Complete || got.OtherBytes != nil || got.Categories[0].State != "unavailable" || got.Categories[0].Bytes != nil || got.Categories[1].State != "absent" || got.Categories[1].Bytes == nil || *got.Categories[1].Bytes != 0 {
		t.Fatalf("unknown disguised as zero: %+v %v", got, err)
	}
	if _, err := openStorageDirectory(filepath.Join(link, "nested")); err == nil {
		t.Fatal("followed ancestor link")
	}
}

func TestStorageOpenedDescriptorSurvivesReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "original")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "kept"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := openStorageDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	n := uint64(0)
	c := storageTestCategory("opened", path)
	c.State = "complete"
	c.Bytes = &n
	scanner := storageScanner{ctx: context.Background(), device: st.Dev, seen: map[storageIdentity]bool{}, limit: 100, categoryLimit: 100}
	scanner.walk(&c, dir, 0, false)
	if c.State != "complete" || c.Scanned != 2 || n == 0 {
		t.Fatalf("substituted path instead of descriptor: %+v", c)
	}
	if _, err = openStorageDirectory(path); err == nil {
		t.Fatal("reopened replacement link")
	}
}

func TestStorageForeignMountExcluded(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated Linux root mount capability")
	}
	root := t.TempDir()
	mount := filepath.Join(root, "foreign")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", mount, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mount, 0); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(mount, "foreign-data"), make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := collectStorageUsage(context.Background(), root, []core.FileStorageCategory{storageTestCategory("root", root), storageTestCategory("foreign", mount)}, 100, 100)
	if err != nil || !got.Complete || !got.Reconciled || got.Categories[0].ForeignMounts != 1 || got.Categories[1].State != "excluded" || got.Categories[1].ForeignMounts != 1 || got.Categories[1].Bytes == nil || *got.Categories[1].Bytes != 0 {
		t.Fatalf("foreign mount counted: %+v %v", got, err)
	}
	output, err := exec.Command("du", "-x", "-s", "-B1", root).Output()
	if err != nil {
		t.Fatal(err)
	}
	n, e := strconv.ParseUint(strings.Fields(string(output))[0], 10, 64)
	if e != nil || n != *got.Categories[0].Bytes {
		t.Fatalf("mount exclusion differs from du: %s %+v", output, got)
	}
}

func TestStorageRouteRefusesCustomDirectories(t *testing.T) {
	r := httptest.NewRecorder()
	New(Config{SitesDir: t.TempDir()}).Handler().ServeHTTP(r, httptest.NewRequest("GET", "/v1/storage/usage?path=/etc", nil))
	if r.Code != 400 {
		t.Fatalf("custom root accepted: %d %s", r.Code, r.Body)
	}
}
