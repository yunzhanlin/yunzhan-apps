//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// A successful enforcement fingerprint does not prove that event evidence is
// healthy. Serialize this bounded observation with rotation, recovery and
// deletion; a pending first index must not look like an empty healthy archive.
func (s *Service) wafBodyLogHealth(ctx context.Context) error {
	lock, err := s.lockWAFObservation()
	if err != nil {
		return err
	}
	defer lock.Close()
	return s.wafBodyLogHealthLocked(ctx)
}

// Version migration already owns the exclusive WAF lock. Do not recursively
// acquire it, and do not skip log health either. An actual open file descriptor
// with this process's kernel FLOCK record is required to reuse the lock.
func (s *Service) verifyWAFHealthLock(lock *os.File) error {
	if lock == nil {
		return errors.New("缺少实际 WAF 事务锁")
	}
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	pathInfo, pathErr := os.Lstat(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"))
	if !ok || pathErr != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("WAF 事务锁文件身份不一致")
	}
	data, err := readModuleProcFile("/proc/locks", 1<<20)
	if err != nil || !moduleFlockOwner(string(data), os.Getpid(), uint64(stat.Dev), stat.Ino) {
		return errors.New("WAF 事务锁未由当前执行进程持有")
	}
	return nil
}

func (s *Service) wafBodyLogHealthUnderLock(ctx context.Context, lock *os.File) error {
	if err := s.verifyWAFHealthLock(lock); err != nil {
		return err
	}
	return s.wafBodyLogHealthLocked(ctx)
}

func (s *Service) wafBodyLogHealthLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	log, err := s.readWAFBodyEventsLocked()
	if err != nil {
		return err
	}
	if !log.Available || log.LegacyLog || log.Rejected > 0 || log.CapacityExhausted {
		return errors.New("当前元数据不可用、异常或达到写入上限")
	}
	stages, err := s.wafBodyLogIndexStages(ctx)
	if err != nil {
		return err
	}
	if len(stages) != 0 {
		return errors.New("存在未提交索引残件，未当成有效备份或成功轮转")
	}
	// Validates every completed/retained file's full digest as well as pending
	// records; an unrelated pending operation cannot hide a corrupt snapshot.
	recovery, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil {
		return err
	}
	if len(recovery) != 0 {
		return errors.New("日志复制、轮转或删除未确认完成")
	}
	archives, err := s.wafBodyLogArchives()
	if err != nil {
		return err
	}
	for _, archive := range archives {
		if archive.State != "completed" {
			return errors.New("已保留未完成快照或原意图，轮转结果仍未知")
		}
	}
	return nil
}
