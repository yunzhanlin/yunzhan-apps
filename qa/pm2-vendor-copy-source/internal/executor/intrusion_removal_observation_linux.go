//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"
)

// This computes a read-only underlying candidate. It neither uninstalls an
// app nor grants write permission. The durable prepare/controller must still
// bind fresh file/daemon/kernel observations and the actual original queue.
// Only our newly generated private copy chooses the fixed client's -c root.
func (s *Service) readIntrusionRemovalCandidate(ctx context.Context, lock *os.File, before intrusionConfigurationTree, jail hardeningJournalFile, current intrusionRuntimeState, beforeIdentity string) (out intrusionRemovalCandidate, observationErr error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	copy, err := s.newIntrusionRemovalCopy(ctx, lock, before, jail)
	if err != nil {
		return out, err
	}
	defer func() {
		// Cancellation or unknown replacement keeps private evidence rather
		// than granting a fresh background cleanup/mutation authority.
		if err := s.closeIntrusionRemovalCopy(ctx, lock, copy); err != nil {
			observationErr = errors.Join(observationErr, errors.New("卸载候选副本未完成受限清理；保留私有证据，未删除未知对象"))
		}
		if observationErr != nil {
			out = intrusionRemovalCandidate{}
		}
	}()
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return out, err
	}
	raw, err := s.Config.Run(ctx, "/usr/bin/python3", "-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate", copy.root.Name())
	if err != nil || ctx.Err() != nil {
		return out, errors.New("底层卸载候选的固定配置测试未完成；未重试、重载或删除源配置")
	}
	copyAfter, err := s.readIntrusionConfigurationTreeAt(ctx, copy.root.Name())
	if err != nil || !reflect.DeepEqual(copy.tree, copyAfter) {
		return out, errors.New("底层卸载候选在配置测试期间改变；未采用不完整副本")
	}
	sourceAfter, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil || !reflect.DeepEqual(before, sourceAfter) {
		return out, errors.New("源完整配置在底层候选测试期间改变；未恢复旧配置或采用候选")
	}
	if err := s.intrusionRemovalCopyCurrent(lock, copy); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return intrusionRemovalCandidateDecode([]byte(raw), current, beforeIdentity)
}
