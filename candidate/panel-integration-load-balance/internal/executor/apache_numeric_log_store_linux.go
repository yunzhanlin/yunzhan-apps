//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// No caller-selectable source, output path, service command, account or lock.
func (s *Service) apacheNumericLogService() *Service {
	return &Service{Config: s.Config, fileTransactionApplication: "apache-waf"}
}
func (s *Service) openApacheNumericLog(writable bool) (*os.File, error) {
	if err := s.wafOwnedDirectory(s.systemPath(apacheBodyMetadataDirectory), false); err != nil {
		return nil, err
	}
	directory, err := os.Lstat(s.systemPath(apacheBodyMetadataDirectory))
	if err != nil || directory.Mode().Perm() != 0755 || directory.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || s.Config.SystemRoot == "/" && directory.Sys().(*syscall.Stat_t).Gid != 0 {
		return nil, errors.New("Apache 数值目录归属或权限异常")
	}
	uid, gid, err := apacheBodyWorkerAccount()
	if s.Config.SystemRoot != "/" {
		uid, gid, err = os.Geteuid(), os.Getegid(), nil
	} // Internal isolated filesystem fixture, never an HTTP authority.
	if err != nil {
		return nil, err
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if writable {
		flags = os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	}
	path := s.systemPath(apacheBodyMetadataLog)
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 0 || st.Size() > apacheNumericLogLimit {
		f.Close()
		return nil, errors.New("Apache 数值日志类型、权限或容量异常")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) || owner.Nlink != 1 {
		f.Close()
		return nil, errors.New("Apache 数值日志固定账户或链接数异常")
	}
	return f, nil
}
func (s *Service) verifyApacheNumericLock(lock *os.File) error {
	if s.fileTransactionApplication != "apache-waf" {
		return errors.New("缺少固定 Apache 日志适配器")
	}
	if lock == nil {
		return errors.New("缺少实际 WAF 事务锁")
	}
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	pathInfo, pathErr := os.Lstat(filepath.Join(s.moduleDir("apache-waf"), "waf-configuration.lock"))
	if !ok || pathErr != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("WAF 事务锁文件身份不一致")
	}
	// The global lock list is not a descriptor witness: another independently
	// opened fd in this process can name the same inode without owning its lock.
	// Its seq-file walk can also miss a held entry during unrelated lock churn.
	// Control pins this actual fd against Close/reuse while inspecting fdinfo.
	raw, err := lock.SyscallConn()
	if err != nil {
		return err
	}
	owned := false
	err = raw.Control(func(fd uintptr) {
		var current syscall.Stat_t
		if syscall.Fstat(int(fd), &current) != nil || current.Dev != stat.Dev || current.Ino != stat.Ino || current.Mode != stat.Mode || current.Uid != stat.Uid || current.Nlink != 1 {
			return
		}
		data, readErr := readModuleProcFile("/proc/self/fdinfo/"+strconv.FormatUint(uint64(fd), 10), 16<<10)
		if readErr != nil || !wafDescriptorExclusiveFlock(data, os.Getpid(), uint64(current.Dev), current.Ino) {
			return
		}
		named, namedErr := os.Lstat(filepath.Join(s.moduleDir("apache-waf"), "waf-configuration.lock"))
		owned = namedErr == nil && os.SameFile(info, named) && named.Mode() == info.Mode()
	})
	if err != nil || !owned {
		return errors.New("WAF 事务锁未由当前执行进程持有")
	}
	return nil
}

func (s *Service) apacheNumericLogHealthLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stages, err := s.apacheNumericLogIndexStages(ctx)
	if err != nil {
		return err
	}
	if len(stages) != 0 {
		return errors.New("Apache 有未提交日志索引，未当成正常库存")
	}
	pending, err := s.apacheNumericLogRecoveryEntries(ctx)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("Apache 日志维护未确认完成")
	}
	_, err = s.apacheNumericLogArchives()
	return err
}
