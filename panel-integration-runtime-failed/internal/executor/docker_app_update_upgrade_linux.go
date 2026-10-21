//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// No mkdir, lock creation, recovery or Docker access. A shared existing store
// lease blocks new admissions while each original run lease proves quiescence.
// Call under the global program/runtime leases again before program mutation.
func (s memcachedUpdateJournalStore) checkProgramUpgrade(ctx context.Context) error {
	bad := errors.New("Memcached 原生更新、私有证据或运行锁未核对结束；阻止程序升级且不重放")
	base, err := geoJobDirectory(s.base, false)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return bad
	}
	defer base.Close()
	lock, err := base.OpenFile("store.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return bad
	}
	defer lock.Close()
	opened, e1 := lock.Stat()
	visible, e2 := base.Lstat("store.lock")
	if e1 != nil || e2 != nil || !moduleRecordInfo(opened, false, false) || opened.Size() != 0 || !geoStoreStableInfo(opened, visible) || unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil || !base.current() {
		return bad
	}
	inventory := func() (map[string]os.FileInfo, error) {
		dir, err := base.Open(".")
		if err != nil {
			return nil, bad
		}
		entries, err := dir.ReadDir(memcachedUpdateJobLimit + 2)
		dir.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(entries) > memcachedUpdateJobLimit+1 {
			return nil, bad
		}
		out := map[string]os.FileInfo{}
		for _, entry := range entries {
			st, err := base.Lstat(entry.Name())
			if err != nil || entry.Name() != "store.lock" && (!core.ValidID(entry.Name()) || !moduleRecordInfo(st, true, false)) {
				return nil, bad
			}
			out[entry.Name()] = st
		}
		if out["store.lock"] == nil || !geoStoreStableInfo(opened, out["store.lock"]) {
			return nil, bad
		}
		return out, nil
	}
	before, err := inventory()
	if err != nil {
		return err
	}
	for id := range before {
		if id == "store.lock" {
			continue
		}
		j, err := s.open(id)
		if err != nil {
			return bad
		}
		lease, err := j.lease()
		if err != nil {
			j.Close()
			return bad
		}
		head, err := j.read()
		if err != nil || !memcachedUpdateSafeTerminal(head.Phase) {
			lease.Close()
			j.Close()
			return bad
		}
		snapshot, err := j.snapshot(ctx)
		safe := err == nil && len(snapshot.Records) > 0 && memcachedUpdateSafeTerminal(snapshot.Records[len(snapshot.Records)-1].Phase) && lease.current()
		lease.Close()
		j.Close()
		if !safe {
			return bad
		}
	}
	after, err := inventory()
	if err != nil || len(before) != len(after) || !base.current() {
		return bad
	}
	for name, st := range before {
		if !geoStoreStableInfo(st, after[name]) {
			return bad
		}
	}
	return ctx.Err()
}
