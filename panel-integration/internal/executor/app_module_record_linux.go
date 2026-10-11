//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

// SecurityDir is the executor's trusted configured anchor, not an arbitrary
// user path. It can be publicly traversable for other panel facilities, but
// cannot be writable by another user. Every module record stays beneath owned
// 0700 modules/id directories. Existing paths are never chmod/chowned here.
func moduleRecordInfo(info os.FileInfo, dir, anchor bool) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if dir {
		return info.IsDir() && (anchor && info.Mode().Perm()&0022 == 0 && info.Mode().Perm()&0700 == 0700 || !anchor && info.Mode().Perm() == 0700)
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && owner.Nlink == 1
}

type modulePrivateDirectory struct {
	*os.Root
	roots []*os.Root
	paths []string
}

func (d *modulePrivateDirectory) Close() error {
	var first error
	for i := len(d.roots) - 1; i >= 0; i-- {
		if err := d.roots[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Keep every configured-anchor/child handle alive. A renamed or substituted
// named parent cannot make an old detached tree look like current state.
func (d *modulePrivateDirectory) current() bool {
	for i, root := range d.roots {
		opened, err := root.Stat(".")
		visible, visibleErr := os.Lstat(d.paths[i])
		if err != nil || visibleErr != nil || !os.SameFile(opened, visible) ||
			!moduleRecordInfo(opened, true, i == 0) || !moduleRecordInfo(visible, true, i == 0) {
			return false
		}
	}
	return true
}

func (s *Service) moduleRecordDirectory(id string) (*modulePrivateDirectory, error) {
	if _, ok := core.FindAppModule(id); !ok || !filepath.IsAbs(s.Config.SecurityDir) || filepath.Clean(s.Config.SecurityDir) != s.Config.SecurityDir {
		return nil, errors.New("模块安装记录位置或应用身份无效")
	}
	info, err := os.Lstat(s.Config.SecurityDir)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, true, true) {
		return nil, errors.New("模块安装记录根目录身份或权限异常")
	}
	root, err := os.OpenRoot(s.Config.SecurityDir)
	if err != nil {
		return nil, errors.New("模块记录根目录打开期间变化或不可读取")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, true, true) {
		root.Close()
		return nil, errors.New("模块记录根目录读取身份变化")
	}
	d := &modulePrivateDirectory{Root: root, roots: []*os.Root{root}, paths: []string{s.Config.SecurityDir}}
	for _, name := range []string{"modules", id} {
		info, err := root.Lstat(name)
		if err != nil {
			current := d.current()
			d.Close()
			if errors.Is(err, os.ErrNotExist) && !current {
				return nil, errors.New("模块记录父目录身份变化，不能据此认定缺失")
			}
			return nil, err
		}
		if !moduleRecordInfo(info, true, false) {
			d.Close()
			return nil, errors.New("模块安装记录私有目录身份或权限异常")
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			d.Close()
			return nil, errors.New("模块记录目录打开期间变化")
		}
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, true, false) {
			child.Close()
			d.Close()
			return nil, errors.New("模块记录目录读取身份变化")
		}
		root = child
		d.Root = child
		d.roots = append(d.roots, child)
		d.paths = append(d.paths, filepath.Join(d.paths[len(d.paths)-1], name))
	}
	if !d.current() {
		d.Close()
		return nil, errors.New("模块记录目录身份变化")
	}
	return d, nil
}

func (s *Service) moduleInstalledRecord(id string) (map[string]any, error) {
	root, err := s.moduleRecordDirectory(id)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat("installed.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !root.current() {
			return nil, errors.New("模块记录目录变化，不能据此认定未安装")
		}
		return nil, err
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > 4<<20 {
		return nil, errors.New("模块安装记录类型、身份、权限或容量异常")
	}
	f, err := root.OpenFile("installed.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("模块安装记录打开期间变化或不可读取")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, false, false) {
		return nil, errors.New("模块安装记录读取身份变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	after, statErr := f.Stat()
	visible, visibleErr := root.Lstat("installed.json")
	if err != nil || statErr != nil || visibleErr != nil || int64(len(raw)) != info.Size() || !os.SameFile(info, after) || !os.SameFile(info, visible) || info.Size() != after.Size() || info.Size() != visible.Size() || info.ModTime() != after.ModTime() || info.ModTime() != visible.ModTime() || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(visible, false, false) || !root.current() {
		return nil, errors.New("模块安装记录读取期间内容或身份变化")
	}
	var manifest map[string]any
	fields := map[string]bool{"id": true, "version": true, "settings": true, "installed_at": true, "updated_at": true}
	// Reuse the existing duplicate/escaped/case-equivalent JSON key guard.
	// No Apache runtime or policy is invoked by this pure decoder.
	if decodeApacheWAFPrivateJSON(raw, &manifest, fields, 100000) != nil || manifest["id"] != id {
		return nil, errors.New("模块安装记录内容或应用身份无效")
	}
	if value, exists := manifest["version"]; exists {
		version, ok := value.(string)
		cmp, valid := appcatalog.CompareVersions(version, core.SoftwareImplementationVersion(id))
		if !ok || !valid || cmp > 0 {
			return nil, errors.New("模块安装记录版本不能由当前处理器核对")
		}
	}
	if value, exists := manifest["settings"]; exists && value != nil {
		if _, ok := value.(map[string]any); !ok {
			return nil, errors.New("模块安装记录配置结构无效")
		}
	}
	return manifest, nil
}
