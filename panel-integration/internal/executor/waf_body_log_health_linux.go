//go:build linux

package executor

import (
	"context"
	"errors"
)

// A successful enforcement fingerprint does not prove that event evidence is
// healthy. Serialize this bounded observation with rotation, recovery and
// deletion; a pending first index must not look like an empty healthy archive.
func (s *Service) wafBodyLogHealth(ctx context.Context) error {
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
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
