//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"local/panel/internal/core"
)

// Ubuntu's /var/log is normally syslog-group writable. Numerical request
// events have an independent root-only directory; never weaken that ancestor
// check or change the system's log directory to accommodate this application.
const apacheBodyMetadataDirectory = "/var/lib/panel-apache-body"
const apacheBodyMetadataLog = apacheBodyMetadataDirectory + "/events.log"

func verifyApacheBodyMetadataDirectory() error {
	if err := apacheBodyOwnedAncestors(apacheBodyMetadataDirectory); err != nil {
		return err
	}
	f, err := os.OpenFile(apacheBodyMetadataDirectory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0755 || st.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("Apache 请求体事件目录权限异常，未修复或接管")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 {
		return errors.New("Apache 请求体事件目录不是 root:root，未接管")
	}
	current, err := os.Lstat(apacheBodyMetadataDirectory)
	if err != nil || !os.SameFile(st, current) || current.Mode() != st.Mode() {
		return errors.New("Apache 请求体事件目录身份已变化")
	}
	currentOwner, ok := current.Sys().(*syscall.Stat_t)
	if !ok || currentOwner.Uid != 0 || currentOwner.Gid != 0 {
		return errors.New("Apache 请求体事件目录账户已变化")
	}
	return nil
}

// Verify both the prior and next authorities before considering any mutation.
// Retained 'ready' flags, a caller-selected DSO, the Nginx v3 manifest and an
// installed application's version badge cannot authorize a native Apache DSO.
func (s *Service) verifyApacheBodyTransition(ctx context.Context, previous, next core.WAFConfig) error {
	checked := map[string]bool{}
	for _, cfg := range []core.WAFConfig{previous, next} {
		if _, err := core.DecodeApacheWAFNativeBodyConfig(core.WAFSettings(cfg)); err != nil {
			return err
		}
		if !apacheBodyActive(cfg) {
			continue
		}
		if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
			return errors.New("Apache 请求体程序只可在实际受管环境核验，拒绝模拟命令或自定义源码路径")
		}
		if !checked[cfg.Body.EngineJobID] {
			if err := verifyApacheBodyBuildContext(ctx, cfg.Body.EngineJobID); err != nil {
				return err
			}
			checked[cfg.Body.EngineJobID] = true
		}
	}
	return ctx.Err()
}

func apacheBodyWorkerAccount() (int, int, error) {
	u, err := user.Lookup("www-data")
	if err != nil {
		return 0, 0, err
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	if e1 != nil || e2 != nil || uid < 1 || gid < 1 {
		return 0, 0, errors.New("Apache 独立工作账户身份无效")
	}
	return uid, gid, nil
}

// Only create missing directories. Existing group/owner/mode mismatches are
// never 'repaired', nor are failed temporary contents or logs removed. The
// request/parser limits are separate from the required filesystem hard quota.
func (s *Service) prepareApacheBodyStorage(ctx context.Context, cfg core.WAFConfig) error {
	if !apacheBodyActive(cfg) {
		return nil
	}
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
		return errors.New("Apache 请求体缓存仅允许真实受管环境")
	}
	uid, gid, err := apacheBodyWorkerAccount()
	if err != nil {
		return err
	}
	capacity, err := verifyApacheBodyCacheQuota()
	if err != nil {
		return err
	}
	if capacity.AvailableBytes < apacheBodyCacheReserveBytes || capacity.AvailableNodes < 128 {
		return errors.New("Apache 请求体硬限额缓存可用容量不足 32 MiB 或 128 inode，保留内容且未启用")
	}
	entries, err := os.ReadDir(apacheBodyTemporary)
	if err != nil || len(entries) > 64 {
		return errors.New("Apache 请求体缓存目录超过 64 个或不可读取，保留原始内容")
	}
	validate := func(path string) error {
		st, e := os.Lstat(path)
		if e != nil || !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Mode().Perm() != 0700 {
			return errors.New("Apache 站点请求体缓存类型或权限异常")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) {
			return errors.New("Apache 站点请求体缓存不属于固定工作账户，未接管")
		}
		return nil
	}
	existing := map[string]bool{}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) {
			return errors.New("Apache 请求体缓存含未知条目，未删除或覆盖")
		}
		if err := validate(filepath.Join(apacheBodyTemporary, entry.Name())); err != nil {
			return err
		}
		existing[entry.Name()] = true
	}
	// Check the complete capacity before making the first new site directory.
	for _, site := range cfg.Body.Sites {
		if _, active := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); active {
			existing[site.SiteID] = true
		}
	}
	if len(existing) > 64 {
		return errors.New("Apache 请求体缓存保留目录将超过 64 个，未启用")
	}
	// Reject an unprovisioned/foreign event directory or retained invalid log
	// before creating even the first missing site cache leaf.
	if err := verifyApacheBodyMetadataDirectory(); err != nil {
		return err
	}
	if f, err := openApacheBodyMetadataLog(); err == nil {
		if err := f.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, site := range cfg.Body.Sites {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, active := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); !active {
			continue
		}
		path := filepath.Join(apacheBodyTemporary, site.SiteID)
		if err := os.Mkdir(path, 0700); err == nil {
			if err = os.Chown(path, uid, gid); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := validate(path); err != nil {
			return err
		}
	}
	if err := verifyApacheBodyMetadataDirectory(); err != nil {
		return err
	}
	f, err := os.OpenFile(apacheBodyMetadataLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = openApacheBodyMetadataLog()
		if err == nil {
			err = f.Close()
		}
		return err
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	// Set the mode while the creating root still owns the descriptor. The
	// restricted executor deliberately has no CAP_FOWNER; after chown it must
	// not need that broader capability simply to prepare the numerical sink.
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return syncRuntimeDirs(filepath.Dir(apacheBodyMetadataLog))
}

func openApacheBodyMetadataLog() (*os.File, error) {
	if err := verifyApacheBodyMetadataDirectory(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(apacheBodyMetadataLog, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	uid, gid, accountErr := apacheBodyWorkerAccount()
	st, e := f.Stat()
	if e != nil || accountErr != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 0 || st.Size() > 32<<20 {
		f.Close()
		return nil, errors.New("Apache 请求体数值日志类型、权限或大小异常")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) || owner.Nlink != 1 {
		f.Close()
		return nil, errors.New("Apache 请求体数值日志账户或链接数异常")
	}
	return f, nil
}

func (s *Service) prepareApacheBodyTransition(ctx context.Context, source string, previous, next core.WAFConfig) (string, error) {
	prepared, err := transitionApacheBodySource(source, previous, next)
	if err != nil {
		return "", err
	}
	if err := s.verifyApacheBodyTransition(ctx, previous, next); err != nil {
		return "", err
	}
	if err := s.prepareApacheBodyStorage(ctx, next); err != nil {
		return "", err
	}
	return prepared, nil
}
