//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const memcachedUnixAdminStorePath = "/var/lib/panel-executor/memcached-accounts"

type memcachedUnixAdminStore struct {
	root   *os.Root
	path   string
	before os.FileInfo
}

func memcachedUnixAdminDirectoryInfo(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && s.Gid == 0
}

func (s *memcachedUnixAdminStore) current() bool {
	if s == nil || s.root == nil || threatIDSTrustedParents(filepath.Dir(s.path), false) != nil {
		return false
	}
	held, e1 := s.root.Stat(".")
	visible, e2 := os.Lstat(s.path)
	return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) &&
		memcachedUnixAdminDirectoryInfo(visible) && geoStoreStableInfo(s.before, held) && geoStoreStableInfo(held, visible)
}

func openMemcachedUnixAdminStore() (*memcachedUnixAdminStore, error) {
	return openMemcachedUnixAdminStoreAt(memcachedUnixAdminStorePath)
}

// Private trusted-root filesystem fixture seam only. Production accepts no
// path/UID/configuration field and always opens the fixed anchor above.
func openMemcachedUnixAdminStoreAt(path string) (*memcachedUnixAdminStore, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || threatIDSTrustedParents(path, false) != nil {
		return nil, errMemcachedUnixNSS
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errMemcachedUnixNSS
	}
	before, err := root.Stat(".")
	store := &memcachedUnixAdminStore{root: root, path: path, before: before}
	if err != nil || !store.current() {
		root.Close()
		return nil, errMemcachedUnixNSS
	}
	return store, nil
}

type memcachedUnixAdminRecord struct {
	store  *memcachedUnixAdminStore
	name   string
	file   *os.File
	before os.FileInfo
}

func memcachedUnixAdminRecordInfo(info os.FileInfo) bool {
	if !memcachedUnixNSSFileInfo(info, true) || info.Size() > 2048 || info.Mode().Perm() != 0600 {
		return false
	}
	return info.Sys().(*syscall.Stat_t).Gid == 0
}

func (r *memcachedUnixAdminRecord) current() bool {
	if r == nil || r.file == nil || r.store == nil || !r.store.current() {
		return false
	}
	held, e1 := r.file.Stat()
	visible, e2 := r.store.root.Lstat(r.name)
	return e1 == nil && e2 == nil && memcachedUnixAdminRecordInfo(held) && memcachedUnixAdminRecordInfo(visible) &&
		geoStoreStableInfo(r.before, held) && geoStoreStableInfo(held, visible)
}

func (s *memcachedUnixAdminStore) openRecord(name string) (*memcachedUnixAdminRecord, []byte, error) {
	if name != "admin-intent.json" && name != "admin.json" || !s.current() {
		return nil, nil, errMemcachedUnixNSS
	}
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errMemcachedUnixNSS
	}
	before, err := f.Stat()
	if err != nil || !memcachedUnixAdminRecordInfo(before) {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	record := &memcachedUnixAdminRecord{store: s, name: name, file: f, before: before}
	raw, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || int64(len(raw)) != before.Size() || !record.current() {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	return record, raw, nil
}

// Read-only ownership condition for the forthcoming normal Unix worker. This
// never creates a directory/account, adopts a GECOS label, repairs NSS, grants
// an actor, or substitutes for the signed envelope and live kernel peer.
// Intent alone is insufficient, and an incomplete creation stays refused.
func memcachedUnixManagedAdminAccount(ctx context.Context) (memcachedUnixAccount, error) {
	var empty memcachedUnixAccount
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return empty, errMemcachedUnixNSS
	}
	store, err := openMemcachedUnixAdminStore()
	if err != nil {
		return empty, err
	}
	defer store.root.Close()
	return memcachedUnixAdminIdentityAt(ctx, store, func(ctx context.Context) (memcachedUnixAccount, error) { return memcachedUnixSystemAccount(ctx, "") })
}
