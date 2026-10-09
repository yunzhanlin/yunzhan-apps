//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// A read-only report may take an existing shared lock, but never initialize
// directories or a lock file. Missing serialization after configuration is an
// unknown condition, not permission to race recovery or retire an archive.
func (s *Service) threatIDSReadLock() (*os.File, error) {
	base := s.moduleDir("network-threat-detection")
	path := filepath.Join(base, "waf-configuration.lock")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		for _, name := range []string{"ids-config.json", "output-rotation.json", "config-transactions/pending.json"} {
			if _, err := os.Lstat(filepath.Join(base, name)); !os.IsNotExist(err) {
				return nil, errors.New("IDS 已有配置或恢复集合但缺少读锁；未宣称完整观察")
			}
		}
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := s.wafOwnedDirectory(base, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		f.Close()
		return nil, errors.New("IDS 观察锁身份或模式异常")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("IDS 正在变更、轮转或恢复；本次只读观察未完成")
		}
		return nil, err
	}
	return f, nil
}
