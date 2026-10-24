//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func intrusionFileRootCurrent(root *os.Root, absolute string) error {
	opened, err := root.Stat(".")
	visible, visibleErr := os.Lstat(absolute)
	if err != nil || visibleErr != nil || !os.SameFile(opened, visible) || !moduleRecordInfo(opened, true, true) || !moduleRecordInfo(visible, true, true) {
		return errors.New("入侵防护固定文件目录的命名身份或权限改变")
	}
	return nil
}

// One fixed-slot filesystem step of an ALREADY DURABLE original transaction.
// No field/path/bytes comes from a command or a persisted executable. Failure
// retains every named partial write as private original-ID evidence; it never
// repairs a third state or silently retries/restarts a service. The controller
// must separately qualify the effective dump/live scalar/kernel boundaries.
func (s *Service) intrusionJournalWriteFile(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, slot int, state string) error {
	if slot < 0 || slot >= 3 || state != "committed" && state != "rolled_back" {
		return errors.New("入侵防护文件变更目标不是固定位置和闭合状态")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	files, _, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, "mixed")
	if err != nil {
		return err
	}
	wanted := plan.Files[slot].After
	if state == "rolled_back" {
		wanted = plan.Files[slot].Before
	}
	paths := s.intrusionJournalPaths()
	absolute := paths[slot]
	parent, name := filepath.Dir(absolute), filepath.Base(absolute)
	if hardeningBackupSame(files[slot], wanted.backup(absolute)) {
		return nil
	}
	if err = s.wafOwnedDirectory(parent, false); err != nil {
		return err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = intrusionFileRootCurrent(root, parent); err != nil {
		return err
	}
	current, err := hardeningReadBackupLimit(root, name, absolute, slot > 0, 16<<10)
	if err != nil || !hardeningBackupSame(current, files[slot]) {
		return errors.New("入侵防护固定目标在文件准备期间改变，未覆盖")
	}
	if !wanted.Exists {
		// Only the original's exact fixed owned bytes may be removed. Fresh
		// install rollback restores known absence; uninstall commits known
		// absence after separately proving the underlying live configuration.
		// Never remove an unregistered, replaced or third-state object.
		restoreAbsence := state == "rolled_back" && !plan.Files[slot].Before.Exists && plan.Files[slot].After.Exists && (slot == 2 || plan.Action == "install")
		removeOwned := state == "committed" && plan.Action == "uninstall" && plan.Files[slot].Before.Exists && !plan.Files[slot].After.Exists
		if !current.existed || !restoreAbsence && !removeOwned {
			return errors.New("入侵防护文件删除不属于原事务的已知缺失恢复")
		}
		if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		last, err := hardeningReadBackupLimit(root, name, absolute, slot > 0, 16<<10)
		if err != nil || !hardeningBackupSame(last, current) {
			return errors.New("入侵防护原受管文件在删除前改变；未删除第三状态")
		}
		if err = root.Remove(name); err != nil {
			return err
		}
		if err = hardeningJournalSync(root); err != nil {
			return err
		}
		if err = intrusionFileRootCurrent(root, parent); err != nil {
			return err
		}
		again, err := hardeningReadBackupLimit(root, name, absolute, true, 16<<10)
		if err != nil || again.existed {
			return errors.New("入侵防护原缺失状态未闭合，保留待恢复记录")
		}
		return s.intrusionJournalRequireOriginal(lock, plan, raw)
	}
	stage := fmt.Sprintf(".intrusion-%s-%s-%s.tmp", plan.ID, plan.Files[slot].Name, core.ID())
	f, err := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	n, err := f.Write(wanted.Data)
	if err == nil && n != len(wanted.Data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Chown(int(wanted.Owner.UID), int(wanted.Owner.GID)); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(wanted.Mode)); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	closed = true
	staged, err := hardeningReadBackupLimit(root, stage, filepath.Join(parent, stage), slot > 0, 16<<10)
	if err != nil || !hardeningBackupSame(staged, wanted.backup(filepath.Join(parent, stage))) {
		return errors.New("入侵防护完整暂存文件未能核对，保留原私有证据")
	}
	if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = intrusionFileRootCurrent(root, parent); err != nil {
		return err
	}
	again, _, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, "mixed")
	if err != nil {
		return err
	}
	if hardeningBackupSame(again[slot], wanted.backup(absolute)) {
		return nil
	}
	if !hardeningBackupSame(again[slot], current) {
		return errors.New("入侵防护目标在暂存期间出现外部变化；保留暂存和原任务")
	}
	if !current.existed {
		dir, err := root.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		if err = unix.Renameat2(int(dir.Fd()), stage, int(dir.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
	} else if err = root.Rename(stage, name); err != nil {
		return err
	}
	if err = hardeningJournalSync(root); err != nil {
		return err
	}
	if err = intrusionFileRootCurrent(root, parent); err != nil {
		return err
	}
	final, err := hardeningReadBackupLimit(root, name, absolute, slot > 0, 16<<10)
	if err != nil || !hardeningBackupSame(final, wanted.backup(absolute)) {
		return errors.New("入侵防护原文件目标持久化后不能完整核对；保留待恢复计划")
	}
	return s.intrusionJournalRequireOriginal(lock, plan, raw)
}
