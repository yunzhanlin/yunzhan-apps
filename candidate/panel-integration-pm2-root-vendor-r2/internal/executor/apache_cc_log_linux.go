//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/core"
)

// Share only the already provisioned root-owned directory/sandbox mount.
// The numerical body sink remains events.log; CC never opens, rotates or
// reinterprets that file or its separate archive/index namespace.
const apacheCCLogDirectory = apacheBodyMetadataDirectory
const apacheCCLogPath = apacheCCLogDirectory + "/cc-events.log"
const apacheCCLogMaxBytes int64 = 32 << 20

func syncApacheCCLogNamespace() error {
	f, err := os.OpenFile(apacheCCLogPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	_ = f.Close()
	if err != nil {
		return err
	}
	// Reuse only the no-follow directory-fsync primitive, not numerical-log
	// record, archive, deletion or replay authority.
	for _, dir := range []string{apacheCCLogDirectory, filepath.Dir(apacheCCLogDirectory)} {
		if err := apacheNumericLogSyncDirectory(dir); err != nil {
			return err
		}
	}
	return nil
}

func apacheCCPolicyMayLog(cfg core.WAFConfig) bool {
	if cfg.ApacheCC == nil || cfg.Policy.Mode == "off" {
		return false
	}
	if cfg.Policy.CCEnabled {
		return true
	}
	for _, site := range cfg.Policy.Sites {
		if site.CCEnabled != nil && *site.CCEnabled && site.Mode != "off" {
			return true
		}
	}
	return false
}

func apacheCCLogFileIdentity(f *os.File, uid, gid int) (os.FileInfo, error) {
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Size() < 0 || st.Size() > apacheCCLogMaxBytes {
		return nil, errors.New("Apache CC 日志类型、权限或容量异常，保留原文件且未接管")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) || owner.Nlink != 1 {
		return nil, errors.New("Apache CC 日志账户或链接数异常，未接管")
	}
	return st, nil
}

// Status and preview never initialize storage. An entirely missing fixed
// namespace is a creation plan; an existing wrong owner/mode/type is an error.
func verifyApacheCCLogStorage(allowAbsent bool) error {
	if err := apacheBodyOwnedAncestors(filepath.Dir(apacheCCLogDirectory)); err != nil {
		return err
	}
	dir, err := os.Lstat(apacheCCLogDirectory)
	if errors.Is(err, os.ErrNotExist) && allowAbsent {
		return nil
	}
	if err != nil {
		return err
	}
	if err := apacheBodyOwnedAncestors(apacheCCLogDirectory); err != nil {
		return err
	}
	owner, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || !dir.IsDir() || dir.Mode().Perm() != 0755 || dir.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || owner.Uid != 0 || owner.Gid != 0 {
		return errors.New("Apache CC 日志目录不是原 root:root 0755 私有命名空间")
	}
	f, err := os.OpenFile(apacheCCLogPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) && allowAbsent {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	uid, gid, err := apacheBodyWorkerAccount()
	if err != nil {
		return err
	}
	_, err = apacheCCLogFileIdentity(f, uid, gid)
	return err
}

// Called only by explicit configuration application, before any policy file
// changes. Existing metadata is never chmodded, chowned, truncated or deleted.
func (s *Service) prepareApacheCCLogStorage(ctx context.Context, cfg core.WAFConfig) error {
	if !apacheCCPolicyMayLog(cfg) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
		return errors.New("Apache CC 日志只允许固定真实受管环境")
	}
	if err := verifyApacheCCLogStorage(true); err != nil {
		return err
	}
	uid, gid, err := apacheBodyWorkerAccount()
	if err != nil {
		return err
	}
	if err := ensureApacheBodyDirectory(apacheCCLogDirectory, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(apacheCCLogPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		if err := verifyApacheCCLogStorage(false); err != nil {
			return err
		}
		return syncApacheCCLogNamespace()
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if err = f.Chown(uid, gid); err != nil {
		return err
	}
	if _, err = apacheCCLogFileIdentity(f, uid, gid); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return syncApacheCCLogNamespace()
}
