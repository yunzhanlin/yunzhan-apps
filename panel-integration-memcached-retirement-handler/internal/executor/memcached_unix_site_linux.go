//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func memcachedUnixSiteBindingMatches(binding, current core.Site) bool {
	if !core.ValidID(current.ID) || binding.ID != current.ID || (current.Status != "running" && current.Status != "stopped") || binding.PHPVersionID == "" || binding.PHPVersionID != current.PHPVersionID || core.ValidatePHPSettings(binding.Settings.PHP) != nil || core.ValidatePHPSettings(current.Settings.PHP) != nil {
		return false
	}
	release, ok := runtimecatalog.Find(current.PHPVersionID)
	if !ok || release.Family != "php" || binding.RuntimeInstanceID != core.PHPInstanceID(binding) || current.RuntimeInstanceID != core.PHPInstanceID(current) || binding.RuntimeInstanceID != current.RuntimeInstanceID {
		return false
	}
	a, e1 := json.Marshal(binding.Settings.PHP)
	b, e2 := json.Marshal(current.Settings.PHP)
	return e1 == nil && e2 == nil && bytes.Equal(a, b)
}

type memcachedUnixSiteFile struct {
	path string
	file *os.File
	info os.FileInfo
	mode os.FileMode
}

func (s *memcachedUnixSiteFile) current() bool {
	if s == nil || s.file == nil || threatIDSTrustedParents(filepath.Dir(s.path), false) != nil {
		return false
	}
	a, e1 := s.file.Stat()
	b, e2 := os.Lstat(s.path)
	if e1 != nil || e2 != nil || !geoStoreStableInfo(s.info, a) || !geoStoreStableInfo(a, b) || !a.Mode().IsRegular() || a.Mode().Perm() != s.mode || a.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeSymlink) != 0 {
		return false
	}
	st, ok := a.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1
}
func memcachedUnixOpenSiteFile(path string, mode os.FileMode) (*memcachedUnixSiteFile, []byte, error) {
	if (mode != 0600 && mode != 0640) || threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, nil, errMemcachedUnixNSS
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	s := &memcachedUnixSiteFile{path: path, file: f, info: info, mode: mode}
	if err != nil || info.Size() <= 0 || info.Size() > 64<<10 || !s.current() {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(raw)) != info.Size() || !s.current() {
		f.Close()
		return nil, nil, errMemcachedUnixNSS
	}
	return s, raw, nil
}

// An NSS comment/name or a Docker label is not website-account ownership.
// Reuse only an existing Root-written PHP binding AND its exact fixed FPM
// configuration, matching a fresh active Core website and full four-file NSS.
// Missing/inactive/static/foreign accounts are never silently created/adopted.
func memcachedUnixOwnedSiteAccount(ctx context.Context, id string) (memcachedUnixAccount, error) {
	var empty memcachedUnixAccount
	if ctx == nil || ctx.Err() != nil || !core.ValidID(id) || os.Geteuid() != 0 {
		return empty, errMemcachedUnixNSS
	}
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return empty, err
	}
	defer reader.Close()
	current, err := (&core.Store{DB: reader.db}).Site(id)
	if err != nil || !reader.current() {
		return empty, errMemcachedUnixNSS
	}
	file, raw, err := memcachedUnixOpenSiteFile(filepath.Join(phpConfigRoot, "bindings", id+".json"), 0600)
	if err != nil {
		return empty, err
	}
	defer file.file.Close()
	var binding core.Site
	if json.Unmarshal(raw, &binding) != nil {
		return empty, errMemcachedUnixNSS
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(raw, canonical) || !memcachedUnixSiteBindingMatches(binding, current) {
		return empty, errMemcachedUnixNSS
	}
	configuration, source, err := memcachedUnixOpenSiteFile(filepath.Join(phpConfigRoot, core.PHPInstanceID(binding), "fpm.conf"), 0640)
	if err != nil {
		return empty, err
	}
	defer configuration.file.Close()
	if string(source) != phpPoolConfiguration(binding, filepath.Join("/srv/panel/sites", id)) {
		return empty, errMemcachedUnixNSS
	}
	account, err := memcachedUnixSystemAccount(ctx, id)
	if err != nil {
		return empty, err
	}
	latest, err := (&core.Store{DB: reader.db}).Site(id)
	if err != nil || !memcachedUnixSiteBindingMatches(binding, latest) || !reader.current() || !file.current() || !configuration.current() || ctx.Err() != nil {
		return empty, errMemcachedUnixNSS
	}
	return account, nil
}
