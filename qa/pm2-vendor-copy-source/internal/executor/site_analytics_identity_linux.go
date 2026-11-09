//go:build linux

package executor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Openat2 is mandatory: neither an account key nor the private include may
// follow a symlink or magic link. No compatibility fallback grants identity.
func analyticsIdentityOpen(path string, directory bool) (*os.File, error) {
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errors.New("采集代理私有文件路径无法安全打开，未应用网站配置")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func analyticsIdentityStat(file *os.File) (unix.Stat_t, error) {
	var s unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &s); err != nil {
		return s, errors.New("采集代理私有文件身份无法核对")
	}
	return s, nil
}

func analyticsIdentityPrivateRead(file *os.File, limit int64, owner uint32) ([]byte, error) {
	before, err := analyticsIdentityStat(file)
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != owner || before.Nlink != 1 || before.Size < 1 || before.Size > limit {
		return nil, errors.New("采集代理私有文件所有者、模式、链接或大小不符")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, afterErr := analyticsIdentityStat(file)
	if err != nil || afterErr != nil || int64(len(raw)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink {
		return nil, errors.New("采集代理私有文件读取中发生变化，未采用其内容")
	}
	return raw, nil
}

func (s *Service) analyticsIdentityAccountKey() ([]byte, error) {
	path := s.systemPath("/var/lib/panel/credential-key")
	file, err := analyticsIdentityOpen(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := analyticsIdentityStat(file)
	if err != nil {
		return nil, err
	}
	if info.Uid != 0 {
		account, lookupErr := user.Lookup("panel")
		if lookupErr != nil {
			return nil, errors.New("采集代理主密钥的面板账户无法核对")
		}
		uid, parseErr := strconv.ParseUint(account.Uid, 10, 32)
		if parseErr != nil || info.Uid != uint32(uid) {
			return nil, errors.New("采集代理主密钥不属于面板账户")
		}
	}
	key, err := analyticsIdentityPrivateRead(file, 32, info.Uid)
	if err != nil || len(key) != 32 {
		return nil, errors.New("采集代理主密钥无法安全核对，不生成替代密钥")
	}
	return key, nil
}

// One bounded immutable include per site/key identity. A partial write or an
// unknown existing file is retained and rejected, never silently replaced.
// Disabling collection removes its site directive; the private file remains
// as original evidence and is not needed by the disabled Nginx configuration.
func (s *Service) prepareSiteAnalyticsIdentity(site core.Site) error {
	if os.Geteuid() != 0 || !core.ValidID(site.ID) || core.ValidateSiteSettings(site.Settings, site.Domain, site.PHPVersionID) != nil || site.Settings.AnalyticsProxyIdentity == "" {
		return errors.New("采集代理私有身份只能由受管 Linux 执行器准备")
	}
	key, err := s.analyticsIdentityAccountKey()
	if err != nil {
		return err
	}
	token, err := core.AnalyticsProxyToken(key, site.ID)
	identity, idErr := core.AnalyticsProxyIdentity(key, site.ID)
	if err != nil || idErr != nil || identity != site.Settings.AnalyticsProxyIdentity {
		return errors.New("采集代理身份与原面板主密钥不匹配，未应用网站配置")
	}
	parent, err := analyticsIdentityOpen(s.systemPath("/etc/panel"), true)
	if err != nil {
		return err
	}
	defer parent.Close()
	parentStat, err := analyticsIdentityStat(parent)
	if err != nil || parentStat.Uid != 0 || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&0022 != 0 {
		return errors.New("采集代理目录的父目录所有者或权限不符")
	}
	created := unix.Mkdirat(int(parent.Fd()), "analytics-ingress", 0700)
	if created != nil && !errors.Is(created, unix.EEXIST) {
		return errors.New("无法建立采集代理私有目录")
	}
	fd, err := unix.Openat(int(parent.Fd()), "analytics-ingress", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("采集代理私有目录无法安全打开")
	}
	dir := os.NewFile(uintptr(fd), "analytics-ingress")
	defer dir.Close()
	dirStat, err := analyticsIdentityStat(dir)
	if err != nil || dirStat.Uid != 0 || dirStat.Mode&07777 != 0700 {
		return errors.New("采集代理私有目录必须属于 root 且权限为 0700")
	}
	if created == nil && unix.Fsync(int(parent.Fd())) != nil {
		return errors.New("采集代理目录持久化未确认，保留现场")
	}
	entries, err := dir.ReadDir(2049)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2048 {
		return errors.New("采集代理私有库存超限或无法读取，未自动删除")
	}
	leaf := filepath.Base(siteAnalyticsIdentityPath(site))
	exists := false
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".conf")
		if !entry.Type().IsRegular() || len(name) != 97 || !core.ValidID(name[:32]) || name[32] != '-' || strings.Trim(name[33:], "0123456789abcdef") != "" || !strings.HasSuffix(entry.Name(), ".conf") {
			return errors.New("采集代理私有库存含未知条目，未自动修复")
		}
		var item unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), entry.Name(), &item, unix.AT_SYMLINK_NOFOLLOW) != nil || item.Mode&unix.S_IFMT != unix.S_IFREG || item.Mode&07777 != 0600 || item.Uid != 0 || item.Nlink != 1 || item.Size < 1 || item.Size > 512 {
			return errors.New("采集代理私有库存身份、模式或大小不符，保留现场")
		}
		if entry.Name() == leaf {
			exists = true
		}
	}
	content := []byte(fmt.Sprintf("# managed collector identity; site=%s\nproxy_set_header %s \"%s\";\nproxy_set_header %s $remote_addr;\n", site.ID, core.AnalyticsProxyTokenHeader, token, core.AnalyticsProxyClientHeader))
	if exists {
		fd, err := unix.Openat(int(dir.Fd()), leaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("原采集代理私有文件无法安全读取")
		}
		file := os.NewFile(uintptr(fd), leaf)
		defer file.Close()
		raw, readErr := analyticsIdentityPrivateRead(file, 512, 0)
		if readErr != nil || !bytes.Equal(raw, content) {
			return errors.New("原采集代理私有文件身份或内容不符，保留现场而不覆盖")
		}
		if file.Sync() != nil || unix.Fsync(int(dir.Fd())) != nil {
			return errors.New("原采集代理私有库存持久化未确认，保留现场")
		}
		return nil
	}
	if len(entries) == 2048 {
		return errors.New("采集代理私有库存已满，未自动删除")
	}
	fd, err = unix.Openat(int(dir.Fd()), leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("采集代理私有文件已存在或无法独占创建，保留现场")
	}
	file := os.NewFile(uintptr(fd), leaf)
	writeErr := func() error {
		if err := file.Chmod(0600); err != nil {
			_ = file.Close()
			return errors.New("采集代理私有文件权限未确认，保留现场")
		}
		n, err := file.Write(content)
		if err != nil || n != len(content) {
			_ = file.Close()
			return errors.New("采集代理私有文件写入结果未确认，保留现场")
		}
		info, statErr := analyticsIdentityStat(file)
		if statErr != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0600 || info.Uid != 0 || info.Nlink != 1 || info.Size != int64(len(content)) {
			_ = file.Close()
			return errors.New("新采集代理私有文件身份发生变化，保留现场")
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return errors.New("采集代理私有文件持久化未确认，保留现场")
		}
		if err := file.Close(); err != nil {
			return errors.New("采集代理私有文件关闭结果未确认，保留现场")
		}
		return nil
	}()
	if writeErr != nil {
		return writeErr
	}
	if unix.Fsync(int(dir.Fd())) != nil {
		return errors.New("采集代理私有库存持久化未确认，保留现场")
	}
	return nil
}
