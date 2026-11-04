//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Read-only queue preflight: never New(), mkdir, create/repair a lock, mount,
// rewrite an index or replay any copy/truncate/removal. The exported CLI still
// has only the fixed production root; the argument is an internal test seam.
func checkApacheNumericLogUpgrade(ctx context.Context, root string) error {
	s := &Service{Config: Config{SystemRoot: root, SecurityDir: filepath.Join(root, "etc/panel/security-apps")}, fileTransactionApplication: "apache-waf"}
	return s.apacheNumericLogReadFence(ctx)
}
func (s *Service) apacheNumericLogReadFence(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(s.moduleDir("apache-waf"), "waf-configuration.lock")
	absent := func() error {
		if _, err := os.Lstat(s.apacheNumericRotationPath()); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Apache 自动日志证据存在但原配置锁缺失；未忽略未知结果")
		}
		if _, err := os.Lstat(s.apacheCCArchiveClosedDirectory()); !errors.Is(err, os.ErrNotExist) {
			return errors.New("CC 原关闭记录存在但配置锁缺失，未创建锁或忽略原请求")
		}
		for _, dir := range []string{s.apacheNumericLogArchiveDirectory(), s.apacheNumericLogIndexDirectory(), s.systemPath("/var/lib/panel-apache-body/retained-index-staging"), s.apacheCCArchiveDirectory(), s.apacheCCArchiveHistoryDirectory()} {
			err := s.apacheNumericLogPrivateDirectory(dir, false)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			return errors.New("Apache 日志证据存在但原配置锁缺失；未创建锁或忽略未知结果")
		}
		return ctx.Err()
	}
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); errors.Is(err, os.ErrNotExist) {
		return absent()
	} else if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return absent()
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("Apache 原日志配置锁身份异常")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return errors.New("Apache 配置或日志维护正在执行，未跨越原操作升级")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err := s.apacheNumericLogHealthLocked(ctx); err != nil {
		return err
	}
	if err := s.apacheCCArchiveReadFence(ctx); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, current) || current.Mode() != st.Mode() {
		return errors.New("Apache 配置锁在日志预检期间变化")
	}
	return ctx.Err()
}
