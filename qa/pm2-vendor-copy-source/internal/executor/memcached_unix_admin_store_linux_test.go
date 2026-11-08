//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMemcachedUnixAdminStoreMetadataDoesNotAdoptGroupReadableOrForeignRecords(t *testing.T) {
	file := memcachedUnixNSSInfoFixture{mode: 0600, size: 128}
	file.stat.Nlink = 1
	if !memcachedUnixAdminRecordInfo(file) {
		t.Fatal("synthetic Root private record refused")
	}
	for _, mode := range []os.FileMode{0400, 0640, 0644, 0660, 0700, os.ModeDir | 0700, os.ModeSymlink | 0600} {
		v := file
		v.mode = mode
		if memcachedUnixAdminRecordInfo(v) {
			t.Fatal("non-exclusive private record authorized", mode)
		}
	}
	for _, change := range []func(*memcachedUnixNSSInfoFixture){
		func(v *memcachedUnixNSSInfoFixture) { v.stat.Uid = 800 },
		func(v *memcachedUnixNSSInfoFixture) { v.stat.Gid = 800 },
		func(v *memcachedUnixNSSInfoFixture) { v.stat.Nlink = 2 },
		func(v *memcachedUnixNSSInfoFixture) { v.size = 2049 },
	} {
		v := file
		change(&v)
		if memcachedUnixAdminRecordInfo(v) {
			t.Fatal("changed owner/group/links/capacity authorized")
		}
	}
	dir := file
	dir.mode = os.ModeDir | 0700
	if !memcachedUnixAdminDirectoryInfo(dir) || memcachedUnixAdminDirectoryInfo(file) || memcachedUnixAdminDirectoryInfo(nil) {
		t.Fatal("fixed Root directory type lost")
	}
	for _, mode := range []os.FileMode{os.ModeDir | 0750, os.ModeDir | 0770, os.ModeDir | os.ModeSetgid | 0700, os.ModeSymlink | 0700} {
		v := dir
		v.mode = mode
		if memcachedUnixAdminDirectoryInfo(v) {
			t.Fatal("group-accessible/special directory authorized")
		}
	}
}

func TestMemcachedUnixAdminStoreActualPrivateDescriptorsNeverRepairOrBorrowReplacement(t *testing.T) {
	anchor := os.Getenv("PANEL_MEMCACHED_UNIX_ACCOUNT_QA_ROOT")
	if os.Geteuid() != 0 || anchor == "" {
		t.Skip("actual Root private filesystem fixture requires explicit own QA anchor")
	}
	if filepath.Clean(anchor) != anchor || !strings.HasPrefix(anchor, "/var/lib/panel-executor/memcached-unix-account-models") || threatIDSTrustedParents(anchor, false) != nil {
		t.Fatal("private native anchor refused")
	}
	// The native harness sets TMPDIR inside its sole Root-owned writable case.
	if !strings.HasPrefix(os.TempDir(), anchor+"/") {
		t.Fatal("native fixture would leave its private case")
	}
	for _, scenario := range []string{"normal", "public-directory", "foreign-directory-group", "directory-link", "public-file", "foreign-file-owner", "foreign-file-group", "symlink", "hardlink", "fifo", "oversize", "replaced-file", "restored-mode-ctime-drift", "detached-parent"} {
		t.Run(scenario, func(t *testing.T) {
			path := t.TempDir()
			raw := memcachedUnixCanonicalRecord(memcachedUnixAdminIntent{1, memcachedUnixAdminName, strings.Repeat("a", 32)})
			file := filepath.Join(path, "admin-intent.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "public-directory":
				os.Chmod(path, 0755)
			case "foreign-directory-group":
				os.Chown(path, 0, 65534)
			case "directory-link":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(path + ".retained") })
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				os.Chmod(file, 0644)
			case "foreign-file-owner":
				os.Chown(file, 65534, 0)
			case "foreign-file-group":
				os.Chown(file, 0, 65534)
			case "symlink":
				if err := os.Rename(file, file+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("admin-intent.json.retained", file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, file+".retained"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(file, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(file, []byte(strings.Repeat("x", 2049)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			store, err := openMemcachedUnixAdminStoreAt(path)
			if scenario == "public-directory" || scenario == "foreign-directory-group" || scenario == "directory-link" {
				if err == nil || store != nil {
					t.Fatal("unsafe anchor adopted")
				}
				after, _ := os.Lstat(path)
				if !geoStoreStableInfo(before, after) {
					t.Fatal("refused anchor was repaired")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer store.root.Close()
			record, body, err := store.openRecord("admin-intent.json")
			if scenario == "public-file" || scenario == "foreign-file-owner" || scenario == "foreign-file-group" || scenario == "symlink" || scenario == "hardlink" || scenario == "fifo" || scenario == "oversize" {
				if err == nil || record != nil || body != nil {
					t.Fatal("unsafe record adopted")
				}
				return
			}
			if err != nil || string(body) != string(raw) {
				t.Fatal("unchanged private record refused", err)
			}
			defer record.file.Close()
			if !record.current() {
				t.Fatal("unchanged held record lost identity")
			}
			switch scenario {
			case "replaced-file":
				if err := os.Rename(file, file+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "restored-mode-ctime-drift":
				// Require an actual kernel ctime transition, not an immediate
				// same-tick chmod/restore with identical observable metadata.
				time.Sleep(25 * time.Millisecond)
				if os.Chmod(file, 0644) != nil || os.Chmod(file, 0600) != nil {
					t.Fatal("fixture mode change failed")
				}
				observed, err := record.file.Stat()
				if err != nil || record.before.Sys().(*syscall.Stat_t).Ctim == observed.Sys().(*syscall.Stat_t).Ctim {
					t.Fatal("own ctime fixture has no observable kernel transition", err)
				}
			case "detached-parent":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(path + ".retained") })
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "normal" {
				if !record.current() {
					t.Fatal("normal descriptor changed")
				}
			} else if record.current() {
				t.Fatal("foreign inode/restored mode/detached parent borrowed authority")
			}
		})
	}
}

func TestMemcachedUnixAdminReaderInvalidContextCannotInitializeAccountStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, value := range []context.Context{nil, ctx} {
		if account, err := memcachedUnixManagedAdminAccount(value); err == nil || account != (memcachedUnixAccount{}) {
			t.Fatal("missing/expired caller reached account ownership")
		}
	}
	var store *memcachedUnixAdminStore
	for _, name := range []string{"admin.json", "../admin.json", "/etc/shadow", "admin.json\x00"} {
		if record, raw, err := store.openRecord(name); err == nil || record != nil || raw != nil {
			t.Fatal("missing store or path alias became authority")
		}
	}
}
