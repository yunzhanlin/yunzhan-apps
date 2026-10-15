//go:build linux

package executor

import (
	"fmt"
	"math"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApacheBodyCacheMountInfoRequiresActualDedicatedRoot(t *testing.T) {
	device := unix.Mkdev(0, 82)
	valid := "23 7 0:82 / /var/cache/panel-apache-body rw,nosuid,nodev,noexec shared:4 - tmpfs tmpfs rw,size=131072k,nr_inodes=4096\n"
	if err := apacheBodyCacheMountInfoRoot([]byte(valid), "23", device); err != nil {
		t.Fatal(err)
	}
	for i, data := range []string{
		"", "23", valid + valid,
		"24 7 0:82 / /var/cache/panel-apache-body rw - tmpfs tmpfs rw\n",
		"23 7 0:81 / /var/cache/panel-apache-body rw - tmpfs tmpfs rw\n",
		"23 7 0:82 /foreign /var/cache/panel-apache-body rw - tmpfs tmpfs rw\n",
		"23 7 0:82 / /var/cache rw - tmpfs tmpfs rw\n",
		"23 7 0:82 / /var/cache/panel-apache-body rw - ext4 /dev/vda1 rw\n",
		"23 7 0:82 / /var/cache/panel-apache-body rw - tmpfs tmpfs rw extra\n",
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if err := apacheBodyCacheMountInfoRoot([]byte(data), "23", device); err == nil {
				t.Fatal("ambiguous, shared, malformed or foreign mount accepted")
			}
		})
	}
}

// Synthetic filesystem fields test only the closed budget predicate; actual
// filesystem/ENOSPC and native Apache business checks are separate evidence.
func TestApacheBodyCacheFilesystemBudgetRejectsSoftOrUnknownLimits(t *testing.T) {
	valid := unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096, Blocks: apacheBodyCacheBytes / 4096, Bfree: 8192, Bavail: 8192, Files: 4096, Ffree: 128, Flags: unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC}
	budget, err := apacheBodyCacheFilesystemBudget(valid)
	if err != nil || budget.TotalBytes != apacheBodyCacheBytes || budget.AvailableBytes != apacheBodyCacheReserveBytes || budget.AvailableNodes != 128 {
		t.Fatal("fixed bounded cache rejected", budget, err)
	}
	for _, kind := range []string{"disk", "zero-block", "huge-block", "unbounded-blocks", "smaller-unreviewed-limit", "larger-limit", "free-overflow", "available-overflow", "inode-unbounded", "inode-overflow", "exec", "dev", "suid", "readonly"} {
		t.Run(kind, func(t *testing.T) {
			bad := valid
			switch kind {
			case "disk":
				bad.Type = unix.EXT4_SUPER_MAGIC
			case "zero-block":
				bad.Bsize = 0
			case "huge-block":
				bad.Bsize = 1 << 30
			case "unbounded-blocks":
				bad.Blocks = math.MaxUint64
			case "smaller-unreviewed-limit":
				bad.Blocks /= 2
			case "larger-limit":
				bad.Blocks *= 2
			case "free-overflow":
				bad.Bfree = math.MaxUint64
			case "available-overflow":
				bad.Bavail = math.MaxUint64
			case "inode-unbounded":
				bad.Files = math.MaxUint64
			case "inode-overflow":
				bad.Ffree = math.MaxUint64
			case "exec":
				bad.Flags &^= unix.ST_NOEXEC
			case "dev":
				bad.Flags &^= unix.ST_NODEV
			case "suid":
				bad.Flags &^= unix.ST_NOSUID
			case "readonly":
				bad.Flags |= unix.ST_RDONLY
			}
			if _, err := apacheBodyCacheFilesystemBudget(bad); err == nil {
				t.Fatal("unknown filesystem budget was accepted", bad)
			}
		})
	}
}

// Predicate evidence only; real readonly systemd namespaces and actual PID1
// dependency restarts must be accepted separately on both Linux architectures.
func TestApacheBodyCacheReadOnlyGuardCannotGrantWritableReadiness(t *testing.T) {
	valid := unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096, Blocks: apacheBodyCacheBytes / 4096, Bfree: 8192, Bavail: 8192, Files: 4096, Ffree: 128, Flags: unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC | unix.ST_RDONLY}
	if _, err := apacheBodyCacheFilesystemBudget(valid); err == nil {
		t.Fatal("readonly cache gained activation readiness")
	}
	if _, err := apacheBodyCacheFilesystemBudgetView(valid, true); err != nil {
		t.Fatal("read-only guard cannot inspect a qualifying physical quota", err)
	}
	for name, change := range map[string]func(*unix.Statfs_t){
		"foreign-fs":      func(v *unix.Statfs_t) { v.Type = unix.EXT4_SUPER_MAGIC },
		"wrong-bytes":     func(v *unix.Statfs_t) { v.Blocks *= 2 },
		"unbounded-nodes": func(v *unix.Statfs_t) { v.Files = 0 },
		"exec":            func(v *unix.Statfs_t) { v.Flags &^= unix.ST_NOEXEC },
		"dev":             func(v *unix.Statfs_t) { v.Flags &^= unix.ST_NODEV },
		"suid":            func(v *unix.Statfs_t) { v.Flags &^= unix.ST_NOSUID },
		"free-overflow":   func(v *unix.Statfs_t) { v.Ffree = math.MaxUint64 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			change(&bad)
			if _, err := apacheBodyCacheFilesystemBudgetView(bad, true); err == nil {
				t.Fatal("read-only view relaxed type, protection or hard quota")
			}
		})
	}
}
