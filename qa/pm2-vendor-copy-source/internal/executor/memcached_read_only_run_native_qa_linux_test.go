//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This explicit native component reads the actual fixed current host queues,
// including every retained original Memcached history. It performs no repair,
// migration, account/service action or application acceptance. The harness runs
// it under the proposed five-capability, ProtectSystem=strict child sandbox,
// with NO ReadWritePaths exception for any executor transaction namespace.
func TestMemcachedReadOnlyUpgradeGuardNativeCurrentHost(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Getenv("PANEL_LBSTREAM_READONLY_GUARD_NATIVE") != "1" {
		t.Skip("explicit fixed current-host read-only admission component only")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("Root-only native readonly observer required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := checkMemcachedRootTransactions(ctx); err != nil {
		t.Fatal("actual complete retained native transactions are not quiescent/readable", err)
	}
	if err := CheckProgramUpgradeQueues(); err != nil {
		var refusal *programQueueNativeRefusal
		if errors.As(err, &refusal) {
			t.Log("actual native admission refusal", refusal.observation.Unit, refusal.observation.LoadState, refusal.observation.ActiveState, refusal.observation.SubState, refusal.observation.JobType, refusal.observation.JobState)
		}
		t.Fatal("actual complete current-host upgrade admission refused", err)
	}
}

func memcachedReadOnlyRunFixture(t *testing.T) (string, *os.Root, func() bool, func(os.FileInfo) bool) {
	t.Helper()
	if os.Getenv("PANEL_NATIVE_QA") != "1" {
		t.Skip("explicit private Linux read-only run-lock component only")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("Root-only trusted fixture required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "run.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	before, _ := root.Stat(".")
	current := func() bool {
		a, e1 := root.Stat(".")
		b, e2 := os.Lstat(path)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(a) && os.SameFile(before, a) && os.SameFile(a, b)
	}
	valid := func(info os.FileInfo) bool { return memcachedUnixJournalFileInfo(info, 0, true) }
	return path, root, current, valid
}

func TestMemcachedReadOnlyRunNativeDescriptorCannotWriteAndStillExcludesWriter(t *testing.T) {
	path, root, current, valid := memcachedReadOnlyRunFixture(t)
	before, err := os.Lstat(filepath.Join(path, "run.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := holdMemcachedReadOnlyRun(root, current, valid)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	flags, err := unix.FcntlInt(lease.file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || !lease.current() {
		t.Fatal("admission gained a writable descriptor", err)
	}
	if _, err := lease.file.Write([]byte("must not be written")); !errors.Is(err, unix.EBADF) {
		t.Fatal("read-only guard could write original inode", err)
	}
	writer, err := root.OpenFile("run.lock", os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("read-only exclusive admission did not exclude actual writer")
	}
	if another, err := holdMemcachedReadOnlyRun(root, current, valid); err == nil || another != nil {
		t.Fatal("second observer gained an original run already held")
	}
	lease.Close()
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("closing observer did not release original read-only flock", err)
	}
	if observer, err := holdMemcachedReadOnlyRun(root, current, valid); err == nil || observer != nil {
		t.Fatal("actual writer was ignored by read-only admission")
	}
	after, err := os.Lstat(filepath.Join(path, "run.lock"))
	body, readErr := os.ReadFile(filepath.Join(path, "run.lock"))
	if err != nil || readErr != nil || len(body) != 0 || !geoStoreStableInfo(before, after) {
		t.Fatal("guard changed original bytes or metadata")
	}
}

func TestMemcachedReadOnlyRunNativeClosedOriginalRefusals(t *testing.T) {
	for _, fault := range []string{"missing", "mode", "nonempty", "symlink", "hardlink", "fifo", "directory", "nil-anchor", "nil-validator", "changed-anchor", "replacement-after-hold"} {
		t.Run(fault, func(t *testing.T) {
			path, root, current, valid := memcachedReadOnlyRunFixture(t)
			name := filepath.Join(path, "run.lock")
			retained := filepath.Join(path, "retained-run")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			var held *memcachedReadOnlyRun
			if fault == "replacement-after-hold" {
				var err error
				held, err = holdMemcachedReadOnlyRun(root, current, valid)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			switch fault {
			case "missing":
				must(os.Rename(name, retained))
			case "mode":
				must(os.Chmod(name, 0644))
			case "nonempty":
				must(os.WriteFile(name, []byte("unknown original"), 0600))
			case "symlink", "hardlink", "fifo", "directory", "replacement-after-hold":
				must(os.Rename(name, retained))
				switch fault {
				case "symlink":
					must(os.Symlink(retained, name))
				case "hardlink":
					must(os.Link(retained, name))
				case "fifo":
					must(unix.Mkfifo(name, 0600))
				case "directory":
					must(os.Mkdir(name, 0700))
				default:
					must(os.WriteFile(name, nil, 0600))
				}
			case "nil-anchor":
				current = nil
			case "nil-validator":
				valid = nil
			case "changed-anchor":
				current = func() bool { return false }
			}
			if fault == "replacement-after-hold" {
				if held.current() {
					t.Fatal("original descriptor adopted replacement inode")
				}
				return
			}
			before, beforeErr := os.Lstat(name)
			if lease, err := holdMemcachedReadOnlyRun(root, current, valid); err == nil || lease != nil {
				t.Fatal("unverifiable original lock gained read-only run authority")
			}
			after, afterErr := os.Lstat(name)
			if errors.Is(beforeErr, os.ErrNotExist) {
				if !errors.Is(afterErr, os.ErrNotExist) {
					t.Fatal("missing original lock was created")
				}
			} else if beforeErr != nil || afterErr != nil || !geoStoreStableInfo(before, after) {
				t.Fatal("refusal repaired or changed original")
			}
		})
	}
}
