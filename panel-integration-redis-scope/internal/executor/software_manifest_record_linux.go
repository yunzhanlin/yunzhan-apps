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

const softwareManifestRecordBytes int64 = 4 << 20

func managedSecuritySoftware(id string) bool {
	return id == "nginx-waf" || id == "system-hardening" || id == "intrusion-prevention"
}

func softwareManifestRecordInfo(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	// Existing root-owned 0640 records are retained by transaction rollback.
	// Accept that legacy mode only for the executor's own group; never other
	// readable/writable records or a foreign group. New writes remain 0600.
	return info.Mode().Perm() == 0600 || info.Mode().Perm() == 0640 && owner.Gid == uint32(os.Getegid())
}

func (s *Service) softwareManifestDirectory() (*os.Root, error) {
	if !filepath.IsAbs(s.Config.SecurityDir) || filepath.Clean(s.Config.SecurityDir) != s.Config.SecurityDir {
		return nil, errors.New("软件安装清单根目录无效")
	}
	info, err := os.Lstat(s.Config.SecurityDir)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, true, true) {
		return nil, errors.New("软件安装清单根目录身份或权限异常")
	}
	root, err := os.OpenRoot(s.Config.SecurityDir)
	if err != nil {
		return nil, errors.New("软件安装清单根目录打开期间变化或不可读取")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, true, true) {
		root.Close()
		return nil, errors.New("软件安装清单根目录读取身份变化")
	}
	return root, nil
}

func (s *Service) softwareManifestAnchorCurrent(root *os.Root) bool {
	opened, err := root.Stat(".")
	visible, visibleErr := os.Lstat(s.Config.SecurityDir)
	return err == nil && visibleErr == nil && os.SameFile(opened, visible) &&
		moduleRecordInfo(opened, true, true) && moduleRecordInfo(visible, true, true)
}

func (s *Service) readSoftwareManifest(id string) (softwareManifest, error) {
	var manifest softwareManifest
	if !managedSecuritySoftware(id) {
		return manifest, errors.New("软件安装清单应用身份无效")
	}
	root, err := s.softwareManifestDirectory()
	if err != nil {
		return manifest, err
	}
	defer root.Close()
	name := id + ".json"
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !s.softwareManifestAnchorCurrent(root) {
			return manifest, errors.New("软件安装清单根目录身份变化；无法据此认定未安装")
		}
		return manifest, err
	}
	if !softwareManifestRecordInfo(info) || info.Size() < 1 || info.Size() > softwareManifestRecordBytes {
		return manifest, errors.New("软件安装清单类型、身份、权限或容量异常")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return manifest, errors.New("软件安装清单打开期间变化或不可读取")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !softwareManifestRecordInfo(opened) {
		return manifest, errors.New("软件安装清单读取身份变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, softwareManifestRecordBytes+1))
	after, statErr := f.Stat()
	visible, visibleErr := root.Lstat(name)
	if err != nil || statErr != nil || visibleErr != nil || int64(len(raw)) != info.Size() ||
		!os.SameFile(info, after) || !os.SameFile(info, visible) || after.Size() != info.Size() ||
		info.ModTime() != after.ModTime() || visible.Size() != info.Size() || visible.ModTime() != info.ModTime() ||
		!softwareManifestRecordInfo(after) || !softwareManifestRecordInfo(visible) || !s.softwareManifestAnchorCurrent(root) {
		return manifest, errors.New("软件安装清单读取期间内容或身份变化")
	}
	fields := map[string]bool{"id": true, "version": true, "settings": true, "previous": true, "installed_at": true}
	if decodeApacheWAFPrivateJSON(raw, &manifest, fields, 100000) != nil || manifest.ID != id {
		return softwareManifest{}, errors.New("软件安装清单内容或应用身份无效")
	}
	cmp, valid := appcatalog.CompareVersions(manifest.Version, core.SoftwareImplementationVersion(id))
	if !valid || cmp > 0 {
		return softwareManifest{}, errors.New("软件安装清单版本不能由当前处理器核对")
	}
	return manifest, nil
}
