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
		named, namedErr := os.Lstat(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"))
		owned = namedErr == nil && os.SameFile(info, named) && named.Mode() == info.Mode()
	})
	if err != nil || !owned {
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
	rotation, _, rotationErr := s.readWAFBodyRotationRecord()
	if rotationErr != nil && !errors.Is(rotationErr, os.ErrNotExist) {
		return rotationErr
	}
	if rotationErr == nil && (rotation.State == "rotating" || rotation.State == "unknown") {
		return errors.New("自动轮转结果仍未知，请按摘要核对；不伪造日志维护成功")
	}
	retention, _, retentionErr := s.readWAFBodyRetentionRecord()
	if retentionErr != nil && !errors.Is(retentionErr, os.ErrNotExist) {
		return retentionErr
	}
	if retentionErr == nil && retention.Operation != nil && (retention.Operation.State == "deleting" || retention.Operation.State == "unknown") {
		return errors.New("自动清理结果仍未知，请按摘要核对；不伪造日志维护成功")
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
