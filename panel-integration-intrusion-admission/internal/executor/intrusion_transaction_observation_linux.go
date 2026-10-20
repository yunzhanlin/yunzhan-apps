//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
)

// Mutation-side reader for independently mixed action/kernel ports. It is
// private, requires the real named EX lock and the byte-exact current immutable
// pending plan, and cannot be selected by a public status parameter. A valid
// observation still grants no mutation authority: file/tree/dump CAS and the
// original durable controller must separately qualify every actual write.
// The workspace has a separate SH/read-only original-record preflight; that
// descriptor cannot be promoted into this writer's required RDWR authority.
func (s *Service) readIntrusionTransactionRuntime(ctx context.Context, lock *os.File, original intrusionJournalPlan, raw []byte) (intrusionRuntimeState, error) {
	var empty intrusionRuntimeState
	if err := s.intrusionJournalRequireOriginal(lock, original, raw); err != nil {
		return empty, err
	}
	out, err := s.readIntrusionRuntime(ctx, &original)
	if err != nil {
		return empty, err
	}
	if err := s.intrusionJournalRequireOriginal(lock, original, raw); err != nil {
		return empty, err
	}
	return out, nil
}

func (s *Service) intrusionJournalRequireOriginal(lock *os.File, original intrusionJournalPlan, raw []byte) error {
	if err := s.intrusionJournalRequireLock(lock); err != nil {
		return err
	}
	plan, record, err := s.intrusionJournalPending()
	if err != nil {
		return err
	}
	encoded, err := intrusionJournalEncode(original)
	if err != nil || plan.ID != original.ID || !bytes.Equal(record, raw) || !bytes.Equal(encoded, raw) {
		return errors.New("入侵防护实际恢复观察没有匹配原完整待恢复计划；未开启宽松读取")
	}
	boot, err := os.ReadFile(s.systemPath("/proc/sys/kernel/random/boot_id"))
	if err != nil || len(boot) > 64 || string(boot) != strings.TrimSpace(string(boot))+"\n" || strings.TrimSpace(string(boot)) != original.BootID {
		return errors.New("入侵防护实际启动身份已偏离原事务；未跨重启接管旧内核句柄")
	}
	return nil
}
