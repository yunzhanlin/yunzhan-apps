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

// Read-only admission fence, not recovery. A saved terminal-looking record
// alone cannot close this new namespace: the complete canonical original
// chain, independent official envelope, quiescent original run inode and
// unchanged namespace must all be observable. No mkdir, repair or Docker call.
func (s memcachedUnixJournalStore) checkProgramUpgrade(ctx context.Context) error {
	return s.checkOriginalTransactions(ctx, nil)
}

func (s memcachedUnixJournalStore) checkOriginalTransactions(ctx context.Context, own *memcachedUnixOriginalRun) error {
	if ctx == nil || ctx.Err() != nil {
		return errMemcachedUnixJournal
	}
	base, err := geoJobDirectory(s.base, false)
	if errors.Is(err, os.ErrNotExist) {
		return ctx.Err()
	}
	if err != nil {
		return errMemcachedUnixJournal
	}
	defer base.Close()
	info, err := base.Stat(".")
	if err != nil || !memcachedUnixJournalRootInfo(info) {
		return errMemcachedUnixJournal
	}
	file, err := base.OpenFile("store.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errMemcachedUnixJournal
	}
	defer file.Close()
	opened, e1 := file.Stat()
	visible, e2 := base.Lstat("store.lock")
	if e1 != nil || e2 != nil || !memcachedUnixJournalFileInfo(opened, 0, true) || !geoStoreStableInfo(opened, visible) || unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil || !base.current() {
		return errMemcachedUnixJournal
	}
	inventory := func() (map[string]os.FileInfo, error) {
		dir, err := base.Open(".")
		if err != nil {
			return nil, errMemcachedUnixJournal
		}
		entries, err := dir.ReadDir(memcachedUnixInstallJobLimit + 2)
		dir.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(entries) > memcachedUnixInstallJobLimit+1 {
			return nil, errMemcachedUnixJournal
		}
		out := map[string]os.FileInfo{}
		for _, entry := range entries {
			info, err := base.Lstat(entry.Name())
			if err != nil || entry.Name() != "store.lock" && (!core.ValidID(entry.Name()) || !memcachedUnixJournalRootInfo(info)) {
				return nil, errMemcachedUnixJournal
			}
			out[entry.Name()] = info
		}
		if out["store.lock"] == nil || !geoStoreStableInfo(opened, out["store.lock"]) {
			return nil, errMemcachedUnixJournal
		}
		return out, nil
	}
	before, err := inventory()
	if err != nil {
		return err
	}
	for id := range before {
		if ctx.Err() != nil {
			return errMemcachedUnixJournal
		}
		if id == "store.lock" {
			continue
		}
		if own != nil && own.j.id == id {
			if s.base != memcachedUnixInstallJobsRoot || own.current(ctx) != nil {
				return errMemcachedUnixJournal
			}
			continue
		}
		j, err := s.open(id)
		if err != nil {
			return errMemcachedUnixJournal
		}
		lease, err := holdMemcachedReadOnlyRun(j.d.root, j.current, func(info os.FileInfo) bool {
			return memcachedUnixJournalFileInfo(info, 0, true)
		})
		if err != nil {
			j.Close()
			return errMemcachedUnixJournal
		}
		head, err := j.read()
		valid := err == nil && (head.Phase == "committed" || head.Phase == "refused")
		if valid {
			authority, verifyErr := j.officialAuthority(ctx)
			latest, readErr := j.read()
			valid = verifyErr == nil && readErr == nil && latest == head && authority.Matches(head.Binding.Version, head.Binding.ManifestSHA256) && authority.CatalogSHA256() == head.CatalogSHA256 && lease.current()
		}
		lease.Close()
		j.Close()
		if !valid {
			return errMemcachedUnixJournal
		}
	}
	after, err := inventory()
	if err != nil || len(before) != len(after) || !base.current() {
		return errMemcachedUnixJournal
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return errMemcachedUnixJournal
		}
	}
	if own != nil && own.current(ctx) != nil {
		return errMemcachedUnixJournal
	}
	current, err := file.Stat()
	if err != nil || !geoStoreStableInfo(opened, current) {
		return errMemcachedUnixJournal
	}
	return ctx.Err()
}

func checkMemcachedRootTransactions(ctx context.Context) error {
	if err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(ctx); err != nil {
		return err
	}
	if err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).checkProgramUpgrade(ctx); err != nil {
		return err
	}
	return (memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}).checkTransactions(ctx, nil)
}

func checkMemcachedDockerTransactions(ctx context.Context) error {
	if err := checkMemcachedRootTransactions(ctx); err != nil {
		return err
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer reader.db.Close()
	if !reader.current() {
		return errMemcachedCoreAuthority
	}
	if err := (&core.Store{DB: reader.db}).CheckMemcachedUnixInstallUpgrade(ctx); err != nil {
		return err
	}
	if err := (&core.Store{DB: reader.db}).CheckMemcachedUnixControlUpgrade(ctx); err != nil {
		return err
	}
	if !reader.current() {
		return errMemcachedCoreAuthority
	}
	return ctx.Err()
}
