//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The descriptor is held through connect and VERSION. Neither a renamed
// ancestor nor a link inside a service-writable directory selects the peer.
func openMemcachedUnixSocketDirectory(path string, account memcachedUnixAccount) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "cache.sock" || len(path) >= 108 || threatIDSTrustedParents(filepath.Dir(filepath.Dir(path)), false) != nil {
		return nil, nil, errMemcachedUnix
	}
	dir := filepath.Dir(path)
	before, err := os.Lstat(dir)
	if err != nil || !memcachedUnixDirectoryInfo(before, account) {
		return nil, nil, errMemcachedUnix
	}
	f, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, errMemcachedUnix
	}
	good := false
	defer func() {
		if !good {
			f.Close()
		}
	}()
	opened, err := f.Stat()
	if err != nil || !memcachedUnixDirectoryInfo(opened, account) || !os.SameFile(before, opened) {
		return nil, nil, errMemcachedUnix
	}
	entries, err := f.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != 1 || entries[0].Name() != "cache.sock" {
		return nil, nil, errMemcachedUnix
	}
	good = true
	return f, opened, nil
}

// Return the same complete fstatat observation used for the owner/type gate;
// there is no second path-based observation from which trust can be borrowed.
func memcachedUnixSocketAt(directory *os.File, account memcachedUnixAccount) (unix.Stat_t, error) {
	var st unix.Stat_t
	if directory == nil || account.UID == 0 || account.GID == 0 || unix.Fstatat(int(directory.Fd()), "cache.sock", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&07777 != 0666 || st.Uid != account.UID || st.Gid != account.GID || st.Nlink != 1 {
		return unix.Stat_t{}, errMemcachedUnix
	}
	return st, nil
}

func sameMemcachedUnixSocketObservation(before, after unix.Stat_t) bool {
	// Connecting through the pinned inode can update access time (including
	// through a bind mount). It is observation, not authority. Keep EVERY
	// other stat field, notably inode/device, owner/mode/link count and both
	// modification timestamps, in the exact continuity comparison.
	after.Atim = before.Atim
	return before == after
}

type memcachedUnixProcess struct{ Start, Device, Inode uint64 }

func memcachedUnixProcessStatus(raw string, account memcachedUnixAccount) bool {
	if account.UID == 0 || account.GID == 0 || !taskSafeProcessStatus(raw, account.UID) {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Gid" && key != "Groups" && key != "CapBnd" {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		fields := strings.Fields(value)
		if key == "CapBnd" {
			if len(fields) != 1 || fields[0] != "0000000000000000" {
				return false
			}
			continue
		}
		if key == "Gid" && len(fields) != 4 || key == "Groups" && len(fields) > 1 {
			return false
		}
		for _, v := range fields {
			if v != strconv.FormatUint(uint64(account.GID), 10) {
				return false
			}
		}
	}
	return len(seen) == 3
}

func memcachedUnixProcessAt(pid int, account memcachedUnixAccount) (memcachedUnixProcess, error) {
	var zero memcachedUnixProcess
	if pid < 2 || pid > 0x7fffffff || account.UID == 0 || account.GID == 0 {
		return zero, errMemcachedUnix
	}
	path := filepath.Join("/proc", strconv.Itoa(pid))
	dir, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, errMemcachedUnix
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		return zero, errMemcachedUnix
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != account.UID || st.Gid != account.GID {
		return zero, errMemcachedUnix
	}
	read := func(name string, limit int64) ([]byte, error) {
		fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errMemcachedUnix
		}
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		i, e := f.Stat()
		if e != nil || !i.Mode().IsRegular() {
			return nil, errMemcachedUnix
		}
		b, e := io.ReadAll(io.LimitReader(f, limit+1))
		if e != nil || int64(len(b)) > limit {
			return nil, errMemcachedUnix
		}
		return b, nil
	}
	parse := func(raw []byte) (uint64, error) {
		p, e := parseProcStat(pid, string(raw), uint64(os.Getpagesize()))
		if e != nil || !strings.HasPrefix(string(raw), strconv.Itoa(pid)+" (") || p.StartTime == 0 || p.State == "Z" || p.State == "X" || p.State == "x" {
			return 0, errMemcachedUnix
		}
		return p.StartTime, nil
	}
	raw, e := read("stat", 8192)
	if e != nil {
		return zero, e
	}
	start, e := parse(raw)
	if e != nil {
		return zero, e
	}
	status, e := read("status", 16384)
	if e != nil || !memcachedUnixProcessStatus(string(status), account) {
		return zero, errMemcachedUnix
	}
	raw, e = read("stat", 8192)
	if e != nil {
		return zero, e
	}
	finish, e := parse(raw)
	visible, e2 := os.Lstat(path)
	if e != nil || start != finish || e2 != nil || !os.SameFile(info, visible) {
		return zero, errMemcachedUnix
	}
	return memcachedUnixProcess{start, uint64(st.Dev), st.Ino}, nil
}
