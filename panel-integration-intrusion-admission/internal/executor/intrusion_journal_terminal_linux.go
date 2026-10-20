//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func (s *Service) intrusionJournalArchiveCurrent(root *os.Root) error {
	if root == nil {
		return errors.New("入侵防护终态缺少原私有归档")
	}
	parent, err := s.intrusionJournalRoot()
	if err != nil {
		return err
	}
	defer parent.Close()
	visible, err := parent.Lstat(intrusionJournalDirectory)
	opened, openedErr := root.Stat(".")
	if err != nil || openedErr != nil || !hardeningJournalDirectoryInfo(visible) || !hardeningJournalDirectoryInfo(opened) || !os.SameFile(visible, opened) || !s.softwareManifestAnchorCurrent(parent) {
		return errors.New("入侵防护原终态归档命名身份改变，未修复或重定向")
	}
	return nil
}

func intrusionTerminalMatches(record intrusionJournalTerminal, plan intrusionJournalPlan, raw []byte, state, recoveryJob string) bool {
	encoded, err := intrusionJournalEncode(record.Plan)
	return err == nil && record.Plan.ID == plan.ID && record.State == state && record.RecoveryJobID == recoveryJob && record.PlanSHA256 == hardeningJournalDigest(raw) && bytes.Equal(encoded, raw)
}

// Publication uses a NEW exclusively created temporary and RENAME_NOREPLACE.
// A partial old temporary is evidence, never input to promotion. An existing
// complete terminal is immutable, even when a caller wants a different state.
// Failures leave the pending plan intact and forbid an accepted-success result.
func (s *Service) intrusionJournalWriteTerminal(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state, recoveryJob string) error {
	record := intrusionJournalTerminal{Format: 1, State: state, PlanSHA256: hardeningJournalDigest(raw), Plan: plan, FinishedAt: core.Now(), RecoveryJobID: recoveryJob}
	encoded, err := intrusionJournalEncode(record)
	if err != nil {
		return err
	}
	if _, err = intrusionJournalTerminalDecode(encoded, plan.ID); err != nil {
		return err
	}
	if err = s.intrusionJournalVerifyState(ctx, lock, plan, raw, state); err != nil {
		return err
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return err
	}
	if previous, exists := inventory.Records[plan.ID]; exists {
		if !intrusionTerminalMatches(previous, plan, raw, state, recoveryJob) {
			return errors.New("入侵防护已有不同不可变终态；未覆盖或回滚已提交原任务")
		}
		return s.intrusionJournalRequireOriginal(lock, plan, raw)
	}
	if len(inventory.Records) >= intrusionJournalRecords || inventory.TemporaryFiles >= intrusionJournalRecords || inventory.Bytes > (16<<20)-int64(len(encoded)) {
		return errors.New("入侵防护终态证据容量不足；未删除原记录或临时证据")
	}
	root, err := s.intrusionJournalArchiveRoot(false)
	if err != nil {
		return err
	}
	if root == nil {
		return errors.New("入侵防护已准备事务的原归档缺失，未重建")
	}
	defer root.Close()
	if err = s.intrusionJournalArchiveCurrent(root); err != nil {
		return err
	}
	stage := ".intrusion-terminal-" + core.ID() + ".tmp"
	f, err := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(encoded)
	if writeErr == nil && n != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	absolute := filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory, stage)
	file, err := hardeningReadBackupLimit(root, stage, absolute, true, intrusionJournalBytes)
	if err != nil || !file.existed || file.mode != 0600 || !bytes.Equal(file.data, encoded) {
		return errors.New("入侵防护新暂存终态不能完整核对，保留原证据")
	}
	if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	if err = s.intrusionJournalArchiveCurrent(root); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = unix.Renameat2(int(dir.Fd()), stage, int(dir.Fd()), plan.ID+".json", unix.RENAME_NOREPLACE); err != nil {
		return errors.New("入侵防护不可变终态发布未闭合；未覆盖目标或隐式重试")
	}
	if err = hardeningJournalSync(root); err != nil {
		return err
	}
	if err = s.intrusionJournalArchiveCurrent(root); err != nil {
		return err
	}
	final, err := s.intrusionJournalInventoryRead()
	if err != nil || !intrusionTerminalMatches(final.Records[plan.ID], plan, raw, state, recoveryJob) {
		return errors.New("入侵防护终态持久化后不能完整核对，保留待恢复记录")
	}
	return s.intrusionJournalRequireOriginal(lock, plan, raw)
}

// Only an exact immutable terminal AND freshly verified actual state may close
// the pending latch. A crash after terminal publication is resolved by this
// same original record, not by executing the historical plan again.
func (s *Service) intrusionJournalCloseTerminal(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state, recoveryJob string) error {
	if err := s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return err
	}
	if !intrusionTerminalMatches(inventory.Records[plan.ID], plan, raw, state, recoveryJob) {
		return errors.New("入侵防护缺少对应原完整计划的不可变终态；未删除待恢复记录")
	}
	if err = s.intrusionJournalVerifyState(ctx, lock, plan, raw, state); err != nil {
		return err
	}
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return errors.New("入侵防护关闭事务前根目录身份改变")
	}
	if err = root.Remove(intrusionPendingName); err != nil {
		return err
	}
	if err = hardeningJournalSync(root); err != nil {
		return err
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return errors.New("入侵防护关闭事务后根目录身份改变")
	}
	if _, _, err = s.intrusionJournalPending(); !errors.Is(err, os.ErrNotExist) {
		return errors.New("入侵防护关闭后出现其他待恢复记录；未删除或报告成功")
	}
	final, err := s.intrusionJournalInventoryRead()
	if err != nil || !intrusionTerminalMatches(final.Records[plan.ID], plan, raw, state, recoveryJob) {
		return errors.New("入侵防护关闭后不可变终态无法完整核对")
	}
	return nil
}
