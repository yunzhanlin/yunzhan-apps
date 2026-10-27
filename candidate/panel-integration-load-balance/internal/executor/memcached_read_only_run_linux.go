//go:build linux

package executor

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Admission must not ask the mount namespace for write access just to prove an
// existing local run inode is quiescent. Unlike a writer lease, this type has
// NO append/issue/finish operation and its descriptor is opened O_RDONLY.
// The unchanged exclusive nonblocking flock still refuses any original writer.
// Production callers hold their original complete namespace inventory/store
// leases and validate the SAME canonical terminal history after taking it.
type memcachedReadOnlyRun struct {
	root   *os.Root
	anchor func() bool
	valid  func(os.FileInfo) bool
	file   *os.File
	before os.FileInfo
}

func holdMemcachedReadOnlyRun(root *os.Root, anchor func() bool, valid func(os.FileInfo) bool) (*memcachedReadOnlyRun, error) {
	bad := errors.New("Memcached 原运行锁无法以只读独占方式核对；保留原事务，不重放")
	if root == nil || anchor == nil || valid == nil || !anchor() {
		return nil, bad
	}
	f, err := root.OpenFile("run.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, bad
	}
	l := &memcachedReadOnlyRun{root: root, anchor: anchor, valid: valid, file: f}
	l.before, err = f.Stat()
	if err != nil || !l.current() || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || !l.current() {
		l.Close()
		return nil, bad
	}
	return l, nil
}

func (l *memcachedReadOnlyRun) current() bool {
	if l == nil || l.root == nil || l.file == nil || l.anchor == nil || l.valid == nil || !l.anchor() {
		return false
	}
	held, e1 := l.file.Stat()
	visible, e2 := l.root.Lstat("run.lock")
	return e1 == nil && e2 == nil && l.valid(held) && l.valid(visible) &&
		geoStoreStableInfo(l.before, held) && geoStoreStableInfo(held, visible) && l.anchor()
}

func (l *memcachedReadOnlyRun) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
		l.file = nil
	}
}
