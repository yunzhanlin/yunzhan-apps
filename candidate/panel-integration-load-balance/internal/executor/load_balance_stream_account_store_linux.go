//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const loadBalanceStreamAccountStorePath = "/var/lib/panel-executor/load-balance-stream-identity"

type loadBalanceStreamOSAccountStore struct {
	root   *os.Root
	path   string
	before os.FileInfo
}

func (s *loadBalanceStreamOSAccountStore) current() bool {
	if s == nil || s.root == nil || threatIDSTrustedParents(filepath.Dir(s.path), false) != nil {
		return false
	}
	held, e1 := s.root.Stat(".")
	visible, e2 := os.Lstat(s.path)
	return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && memcachedUnixAdminDirectoryInfo(visible) &&
		geoStoreStableInfo(s.before, held) && geoStoreStableInfo(held, visible)
}

// Private filesystem-fixture seam only, not an RPC/application argument.
// No creation, permission repair, recursive walk or adoption occurs here.
func openLoadBalanceStreamAccountStoreAt(path string) (*loadBalanceStreamOSAccountStore, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || threatIDSTrustedParents(path, false) != nil {
		return nil, errLoadBalanceStreamAccount
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	before, err := root.Stat(".")
	s := &loadBalanceStreamOSAccountStore{root, path, before}
	if err != nil || !s.closed() {
		root.Close()
		return nil, errLoadBalanceStreamAccount
	}
	return s, nil
}

func (s *loadBalanceStreamOSAccountStore) closed() bool {
	if !s.current() {
		return false
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return false
	}
	defer dir.Close()
	entries, err := dir.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2 {
		return false
	}
	for _, entry := range entries {
		if entry.Name() != "account-intent.json" && entry.Name() != "account.json" {
			return false
		}
		info, err := s.root.Lstat(entry.Name())
		if err != nil || !memcachedUnixAdminRecordInfo(info) {
			return false
		}
	}
	return s.current()
}

type loadBalanceStreamOSAccountRecord struct {
	store  *loadBalanceStreamOSAccountStore
	name   string
	file   *os.File
	before os.FileInfo
	raw    []byte
}

func (r *loadBalanceStreamOSAccountRecord) bytes() []byte { return r.raw }
func (r *loadBalanceStreamOSAccountRecord) close() error {
	clear(r.raw)
	return r.file.Close()
}

func (r *loadBalanceStreamOSAccountRecord) current() bool {
	if r == nil || r.file == nil || r.store == nil || !r.store.closed() {
		return false
	}
	held, e1 := r.file.Stat()
	visible, e2 := r.store.root.Lstat(r.name)
	return e1 == nil && e2 == nil && memcachedUnixAdminRecordInfo(held) && memcachedUnixAdminRecordInfo(visible) &&
		geoStoreStableInfo(r.before, held) && geoStoreStableInfo(held, visible)
}

func (s *loadBalanceStreamOSAccountStore) read(name string) (loadBalanceStreamHeldAccountRecord, error) {
	if name != "account-intent.json" && name != "account.json" || !s.closed() {
		return nil, errLoadBalanceStreamAccount
	}
	file, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	before, err := file.Stat()
	if err != nil || !memcachedUnixAdminRecordInfo(before) {
		file.Close()
		return nil, errLoadBalanceStreamAccount
	}
	record := &loadBalanceStreamOSAccountRecord{store: s, name: name, file: file, before: before}
	raw, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil || int64(len(raw)) != before.Size() || !record.current() {
		file.Close()
		return nil, errLoadBalanceStreamAccount
	}
	record.raw = raw
	return record, nil
}

func (s *loadBalanceStreamOSAccountStore) writeExclusive(name string, raw []byte) error {
	if !s.closed() {
		return errLoadBalanceStreamAccount
	}
	switch name {
	case "account-intent.json":
		if _, err := decodeLoadBalanceStreamAccountIntent(raw); err != nil {
			return err
		}
	case "account.json":
		if _, err := decodeLoadBalanceStreamAccountReceipt(raw); err != nil {
			return err
		}
	default:
		return errLoadBalanceStreamAccount
	}
	before := s.before
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	defer file.Close()
	// Only the newly exclusive inode receives fixed ownership/mode. A failed
	// partial record remains visible and refused; it is never removed/retried.
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errLoadBalanceStreamAccount
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errLoadBalanceStreamAccount
	}
	if file.Sync() != nil || ruleFeedStoreSync(s.root) != nil {
		return errLoadBalanceStreamAccount
	}
	held, e1 := file.Stat()
	visible, e2 := s.root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixAdminRecordInfo(held) || !geoStoreStableInfo(held, visible) {
		return errLoadBalanceStreamAccount
	}
	now, err := s.root.Stat(".")
	if err != nil || !os.SameFile(before, now) || !memcachedUnixAdminDirectoryInfo(now) {
		return errLoadBalanceStreamAccount
	}
	s.before = now
	if !s.closed() {
		return errLoadBalanceStreamAccount
	}
	return nil
}

// Read-only ownership check for the future fixed Root controller. Missing or
// incomplete creation is refused; no system command/account mutation is wired.
func loadBalanceStreamManagedSystemIdentity(ctx context.Context) (loadBalanceStreamIdentity, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return loadBalanceStreamIdentity{}, errLoadBalanceStreamAccount
	}
	store, err := openLoadBalanceStreamAccountStoreAt(loadBalanceStreamAccountStorePath)
	if err != nil {
		return loadBalanceStreamIdentity{}, err
	}
	defer store.root.Close()
	return loadBalanceStreamManagedIdentityAt(ctx, store, loadBalanceStreamSystemIdentity)
}
