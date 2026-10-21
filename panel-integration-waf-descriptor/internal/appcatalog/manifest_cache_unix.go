//go:build linux || darwin

package appcatalog

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// The configured DataDir and its ancestors are the Core's trusted anchor.
// Only the private packages tree is created/operated here; arbitrary plugin
// paths, symlinks, foreign owners, hardlinked records and public caches are not
// accepted. No existing directory is chmod/chowned to make it pass.
type manifestCache struct{ root *os.Root }

func manifestPrivateInfo(info os.FileInfo, dir bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		((dir && info.IsDir() && info.Mode().Perm()&0700 == 0700) || (!dir && info.Mode().IsRegular() && st.Nlink == 1 && info.Mode().Perm() == 0600))
}

func openManifestCache(base string, item CatalogItem) (*manifestCache, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return nil, errors.New("应用包缓存必须使用规范的绝对私有路径")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	before, err := os.Lstat(base)
	if err != nil || !manifestPrivateInfo(before, true) {
		return nil, errors.New("应用包缓存目录不是本用户的私有普通目录")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	fail := func() (*manifestCache, error) {
		root.Close()
		return nil, errors.New("应用包缓存目录身份、所有者或权限异常")
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(before, current) || !manifestPrivateInfo(current, true) {
		return fail()
	}
	for _, name := range []string{item.ID, item.Version} {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			root.Close()
			return nil, err
		}
		info, err := root.Lstat(name)
		if err != nil || !manifestPrivateInfo(info, true) {
			return fail()
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			root.Close()
			return nil, err
		}
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(info, opened) || !manifestPrivateInfo(opened, true) {
			child.Close()
			return fail()
		}
		root.Close()
		root = child
	}
	return &manifestCache{root}, nil
}

func (c *manifestCache) Close() error { return c.root.Close() }

func (c *manifestCache) Read() ([]byte, error) {
	info, err := c.root.Lstat("manifest.json")
	if err != nil {
		return nil, err
	}
	if !manifestPrivateInfo(info, false) || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, errors.New("应用包缓存文件身份、权限或容量异常，未使用或覆盖")
	}
	f, err := c.root.OpenFile("manifest.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !manifestPrivateInfo(opened, false) {
		return nil, errors.New("应用包缓存读取身份已变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	after, statErr := f.Stat()
	visible, visibleErr := c.root.Lstat("manifest.json")
	if err != nil || statErr != nil || visibleErr != nil || int64(len(raw)) != info.Size() || !os.SameFile(info, after) || !os.SameFile(info, visible) || after.Size() != info.Size() || after.ModTime() != info.ModTime() || !manifestPrivateInfo(after, false) || !manifestPrivateInfo(visible, false) {
		return nil, errors.New("应用包缓存读取期间身份或内容变化")
	}
	return raw, nil
}

func (c *manifestCache) Publish(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return errors.New("应用包缓存写入容量无效")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".manifest-" + hex.EncodeToString(nonce[:])
	f, err := c.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer c.root.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Hard-link publication is exclusive and never overwrites an existing
	// record. Remove our temporary name before future readers check Nlink == 1.
	if err = c.root.Link(name, "manifest.json"); errors.Is(err, os.ErrExist) {
		previous, readErr := c.Read()
		if readErr == nil && bytes.Equal(previous, raw) {
			return nil
		}
		return errors.New("并发应用包缓存身份或内容不同，未覆盖原记录")
	} else if err != nil {
		return err
	}
	if err = c.root.Remove(name); err != nil {
		return err
	}
	dir, err := c.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
