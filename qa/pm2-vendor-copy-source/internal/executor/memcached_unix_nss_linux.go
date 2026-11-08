//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"os/user"
	"syscall"

	"local/panel/internal/core"
)

type memcachedUnixNSSFile struct {
	path    string
	private bool
	file    *os.File
	before  os.FileInfo
}

func memcachedUnixNSSFileInfo(info os.FileInfo, private bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm()&0133 != 0 {
		// Public passwd/group may be world-readable, never world-writable.
		return false
	}
	if private && info.Mode().Perm()&0037 != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && s.Nlink == 1
}

func (f *memcachedUnixNSSFile) current() bool {
	if f == nil || f.file == nil {
		return false
	}
	held, e1 := f.file.Stat()
	visible, e2 := os.Lstat(f.path)
	return e1 == nil && e2 == nil && memcachedUnixNSSFileInfo(held, f.private) &&
		memcachedUnixNSSFileInfo(visible, f.private) && geoStoreStableInfo(f.before, held) &&
		geoStoreStableInfo(held, visible)
}

func openMemcachedUnixNSSFile(path string) (*memcachedUnixNSSFile, []byte, error) {
	private := false
	switch path {
	case "/etc/passwd", "/etc/group":
	case "/etc/shadow", "/etc/gshadow":
		private = true
	default:
		return nil, nil, errMemcachedUnixNSS
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errMemcachedUnixNSS
	}
	before, err := f.Stat()
	if err != nil || !memcachedUnixNSSFileInfo(before, private) {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	reader := &memcachedUnixNSSFile{path: path, private: private, file: f, before: before}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || int64(len(raw)) != before.Size() || !reader.current() {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	return reader, raw, nil
}

// Fixed Root-only local verification. No API/configuration path or UID is
// accepted. Held descriptors and named identities remain current across all
// four inputs and the independent NSS lookup. Secret bytes never leave this
// scope or become a receipt/log/HTTP field. This is not account provisioning,
// actor permission or container/peer admission.
func memcachedUnixSystemAccount(ctx context.Context, site string) (memcachedUnixAccount, error) {
	var empty memcachedUnixAccount
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || site != "" && !core.ValidID(site) ||
		threatIDSTrustedParents("/etc", false) != nil {
		return empty, errMemcachedUnixNSS
	}
	var sources []*memcachedUnixNSSFile
	var raw [][]byte
	defer func() {
		for _, source := range sources {
			source.file.Close()
		}
		for _, data := range raw {
			clear(data)
		}
	}()
	for _, name := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"} {
		if ctx.Err() != nil {
			return empty, errMemcachedUnixNSS
		}
		file, data, err := openMemcachedUnixNSSFile(name)
		if err != nil {
			return empty, err
		}
		sources, raw = append(sources, file), append(raw, data)
	}
	identity, err := validateMemcachedUnixNSS(raw[0], raw[1], raw[2], raw[3], site)
	if err != nil {
		return empty, err
	}
	account, err := memcachedUnixResolveAccount(site, user.Lookup, memcachedUnixLookupGroup)
	if err != nil || account.UID != identity.UID || account.GID != identity.GID {
		return empty, errMemcachedUnixNSS
	}
	for _, source := range sources {
		if !source.current() {
			return empty, errMemcachedUnixNSS
		}
		s := source.before.Sys().(*syscall.Stat_t)
		if source.private && source.before.Mode().Perm()&0040 != 0 && s.Gid == account.GID {
			return empty, errMemcachedUnixNSS
		}
	}
	if ctx.Err() != nil || threatIDSTrustedParents("/etc", false) != nil {
		return empty, errMemcachedUnixNSS
	}
	return account, nil
}
