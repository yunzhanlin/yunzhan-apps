//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/core"
)

func memcachedUnixDirectoryInfo(info os.FileInfo, account memcachedUnixAccount) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != 0770 || account.UID == 0 || account.GID == 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && s.Gid == account.GID
}

// The base is a fixed Root anchor. Only missing paths are initialized; an
// existing unsafe directory, link, owner or mode is never chmod/chowned into
// apparent trust. Private site groups can write INSIDE their instance, never
// replace the instance directory beneath the Root-owned 0751/0700 base.
func memcachedUnixBaseAt(base string, mode os.FileMode) (*os.Root, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(base) || filepath.Clean(base) != base || (mode != 0700 && mode != 0751) || threatIDSTrustedParents(filepath.Dir(base), false) != nil {
		return nil, errMemcachedUnix
	}
	parent, e := os.OpenRoot(filepath.Dir(base))
	if e != nil {
		return nil, errMemcachedUnix
	}
	defer parent.Close()
	name := filepath.Base(base)
	info, e := parent.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		if parent.Mkdir(name, 0700) != nil {
			return nil, errMemcachedUnix
		}
		created, e := parent.OpenRoot(name)
		if e != nil {
			return nil, errMemcachedUnix
		}
		f, e := created.Open(".")
		if e != nil {
			created.Close()
			return nil, errMemcachedUnix
		}
		// This descriptor is only a newly created Root directory, not an
		// operator's existing object. Account for a restrictive process umask.
		e = f.Chown(0, 0)
		if e == nil {
			e = f.Chmod(mode)
		}
		syncErr := f.Sync()
		f.Close()
		created.Close()
		if e != nil || syncErr != nil || ruleFeedStoreSync(parent) != nil {
			return nil, errMemcachedUnix
		}
	}
	info, e = parent.Lstat(name)
	if e != nil || !info.IsDir() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errMemcachedUnix
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 {
		return nil, errMemcachedUnix
	}
	root, e := parent.OpenRoot(name)
	if e != nil {
		return nil, errMemcachedUnix
	}
	opened, e := root.Stat(".")
	visible, e2 := os.Lstat(base)
	if e != nil || e2 != nil || !os.SameFile(info, opened) || !os.SameFile(opened, visible) {
		root.Close()
		return nil, errMemcachedUnix
	}
	return root, nil
}

func prepareMemcachedUnixDirectory(project, site string, account memcachedUnixAccount) error {
	directory, e := core.MemcachedUnixDirectory(project, site)
	if e != nil {
		return e
	}
	mode := os.FileMode(0700)
	if site != "" {
		mode = 0751
	}
	return prepareMemcachedUnixDirectoryAt(filepath.Dir(directory), project, mode, account)
}

func prepareMemcachedUnixDirectoryAt(base, project string, mode os.FileMode, account memcachedUnixAccount) error {
	if !core.ValidID(project) || account.UID == 0 || account.GID == 0 || account.UID > 0x7fffffff || account.GID > 0x7fffffff {
		return errMemcachedUnix
	}
	root, e := memcachedUnixBaseAt(base, mode)
	if e != nil {
		return e
	}
	defer root.Close()
	if _, e = root.Lstat(project); !errors.Is(e, os.ErrNotExist) {
		return errors.New("Memcached Socket 目录已存在，保留原内容与任务；未重新创建")
	}
	if root.Mkdir(project, 0700) != nil {
		return errMemcachedUnix
	}
	dir, e := root.OpenRoot(project)
	if e != nil {
		return errMemcachedUnix
	}
	defer dir.Close()
	f, e := dir.Open(".")
	if e != nil {
		return errMemcachedUnix
	}
	defer f.Close()
	if f.Chown(0, int(account.GID)) != nil || f.Chmod(0770) != nil || f.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return errMemcachedUnix
	}
	opened, e := f.Stat()
	visible, e2 := root.Lstat(project)
	if e != nil || e2 != nil || !memcachedUnixDirectoryInfo(opened, account) || !os.SameFile(opened, visible) {
		return errMemcachedUnix
	}
	return nil
}

func validateMemcachedUnixDirectory(project, site string, account memcachedUnixAccount) error {
	directory, e := core.MemcachedUnixDirectory(project, site)
	if e != nil {
		return e
	}
	mode := os.FileMode(0700)
	if site != "" {
		mode = 0751
	}
	// Validation must not initialize an absent base or a partial instance.
	base := filepath.Dir(directory)
	info, e := os.Lstat(base)
	if e != nil || !info.IsDir() || info.Mode().Perm() != mode || threatIDSTrustedParents(base, false) != nil {
		return errMemcachedUnix
	}
	baseOwner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || baseOwner.Uid != 0 || baseOwner.Gid != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errMemcachedUnix
	}
	parent, e := os.OpenRoot(base)
	if e != nil {
		return errMemcachedUnix
	}
	defer parent.Close()
	info, e = parent.Lstat(project)
	if e != nil || !memcachedUnixDirectoryInfo(info, account) {
		return errMemcachedUnix
	}
	dir, e := parent.OpenRoot(project)
	if e != nil {
		return errMemcachedUnix
	}
	defer dir.Close()
	opened, e := dir.Stat(".")
	visible, e2 := parent.Lstat(project)
	if e != nil || e2 != nil || !os.SameFile(info, opened) || !os.SameFile(opened, visible) {
		return errMemcachedUnix
	}
	return nil
}
