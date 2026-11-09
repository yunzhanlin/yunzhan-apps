//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

var hardeningJournalTemporary = regexp.MustCompile(`^\.panel-write-[0-9]+$`)

func hardeningJournalDirectoryInfo(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid()) && info.Mode() == os.ModeDir|0700
}

func (s *Service) hardeningJournalArchiveRoot(create bool) (*os.Root, error) {
	root, err := s.hardeningJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(hardeningJournalDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, nil
		}
		if err = root.Mkdir(hardeningJournalDirectory, 0700); err != nil {
			return nil, err
		}
		if err = hardeningJournalSync(root); err != nil {
			return nil, err
		}
		info, err = root.Lstat(hardeningJournalDirectory)
	}
	if err != nil {
		return nil, err
	}
	if !hardeningJournalDirectoryInfo(info) {
		return nil, errors.New("加固事务归档目录身份或权限无效，未修复")
	}
	child, err := root.OpenRoot(hardeningJournalDirectory)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !hardeningJournalDirectoryInfo(opened) || !s.softwareManifestAnchorCurrent(root) {
		child.Close()
		return nil, errors.New("加固事务归档目录打开期间改变")
	}
	return child, nil
}

type hardeningJournalInventory struct {
	Records        map[string]hardeningJournalTerminal
	TemporaryFiles int
	Bytes          int64
}

// Root-private incomplete atomic-write temporaries are not terminal authority.
// They are retained, bounded and reported; never parsed as success or deleted.
func (s *Service) hardeningJournalInventoryRead() (hardeningJournalInventory, error) {
	result := hardeningJournalInventory{Records: map[string]hardeningJournalTerminal{}}
	root, err := s.hardeningJournalArchiveRoot(false)
	if err != nil || root == nil {
		return result, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return result, err
	}
	entries, err := dir.ReadDir(hardeningJournalRecords*2 + 1)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > hardeningJournalRecords*2 {
		return result, errors.New("加固事务完整库存超过固定容量")
	}
	for _, entry := range entries {
		name := entry.Name()
		if hardeningJournalTemporary.MatchString(name) {
			info, err := root.Lstat(name)
			if err != nil || !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > hardeningJournalBytes {
				return result, errors.New("加固事务临时证据类型、身份或容量异常")
			}
			result.TemporaryFiles++
			result.Bytes += info.Size()
			if result.TemporaryFiles > hardeningJournalRecords {
				return result, errors.New("加固事务临时证据容量已满，未删除原证据")
			}
			continue
		}
		if len(name) != 37 || name[32:] != ".json" || !core.ValidID(name[:32]) {
			return result, errors.New("加固事务库存含未知条目，未忽略或清理")
		}
		file, err := hardeningReadBackupLimit(root, name, filepath.Join(s.Config.SecurityDir, hardeningJournalDirectory, name), true, hardeningJournalBytes)
		if err != nil || !file.existed || file.mode != 0600 {
			return result, errors.New("加固事务终态文件身份、权限或容量无法核对")
		}
		terminal, err := hardeningJournalTerminalDecode(file.data, name[:32])
		if err != nil {
			return result, err
		}
		result.Records[terminal.Plan.ID] = terminal
		result.Bytes += int64(len(file.data))
		if len(result.Records) > hardeningJournalRecords || result.Bytes > 16<<20 {
			return result, errors.New("加固事务完整库存字节预算已满")
		}
	}
	if result.Bytes > 16<<20 {
		return result, errors.New("加固事务完整库存字节预算已满")
	}
	return result, nil
}

func (s *Service) hardeningJournalRequireClosed() error {
	_, _, err := s.hardeningJournalPending()
	if !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return hardeningJournalError("原记录核对", err)
		}
		return errors.New("存在未闭合的加固事务；须先核对原任务并显式恢复，未重复应用")
	}
	_, err = s.hardeningJournalInventoryRead()
	return err
}

// Caller holds the same exclusive cross-process hardening mutation lock.
// A failed/partial exclusive prepare is retained and blocks later mutation.
func (s *Service) hardeningJournalPrepare(plan hardeningJournalPlan) ([]byte, error) {
	if err := hardeningJournalValidate(plan); err != nil {
		return nil, err
	}
	if err := s.hardeningJournalRequireClosed(); err != nil {
		return nil, err
	}
	inventory, err := s.hardeningJournalInventoryRead()
	if err != nil {
		return nil, err
	}
	if _, exists := inventory.Records[plan.ID]; exists {
		return nil, errors.New("该原任务已有不可变终态回执，未重新准备")
	}
	if len(inventory.Records) >= hardeningJournalRecords {
		return nil, errors.New("加固事务终态库存已满，未删除恢复证据")
	}
	archive, err := s.hardeningJournalArchiveRoot(true)
	if err != nil {
		return nil, err
	}
	archive.Close()
	root, err := s.hardeningJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := hardeningJournalEncode(plan)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(hardeningPendingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, hardeningJournalError("准备持久化", err)
	}
	if closeErr != nil {
		return nil, hardeningJournalError("准备关闭", closeErr)
	}
	if err = hardeningJournalSync(root); err != nil {
		return nil, hardeningJournalError("准备目录持久化", err)
	}
	got, again, err := s.hardeningJournalPending()
	if err != nil || got.ID != plan.ID || !bytes.Equal(again, raw) {
		return nil, errors.New("加固原计划持久化后无法核对，未执行系统变更")
	}
	return raw, nil
}

func (s *Service) hardeningJournalRemoveExact(plan hardeningJournalPlan, raw []byte) error {
	current, again, err := s.hardeningJournalPending()
	if err != nil || current.ID != plan.ID || !bytes.Equal(raw, again) {
		return errors.New("加固待恢复命名记录已改变，未删除")
	}
	root, err := s.hardeningJournalRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Remove(hardeningPendingName); err != nil {
		return err
	}
	return hardeningJournalSync(root)
}

// Terminal publication is immutable at the semantic level. An existing record
// must match the exact original plan/state; it is never rewritten or repaired.
func (s *Service) hardeningJournalWriteTerminal(plan hardeningJournalPlan, raw []byte, state, recoveryJob string) error {
	current, again, err := s.hardeningJournalPending()
	if err != nil || current.ID != plan.ID || !bytes.Equal(raw, again) {
		return errors.New("加固原计划在终态准备期间变化")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.hardeningJournalVerifyState(ctx, plan, state); err != nil {
		return err
	}
	record := hardeningJournalTerminal{Format: 1, State: state, PlanSHA256: hardeningJournalDigest(raw), Plan: plan, FinishedAt: core.Now(), RecoveryJobID: recoveryJob}
	if err = hardeningJournalTerminalValidate(record); err != nil {
		return err
	}
	inventory, err := s.hardeningJournalInventoryRead()
	if err != nil {
		return err
	}
	if prior, exists := inventory.Records[plan.ID]; exists {
		priorRaw, _ := hardeningJournalEncode(prior.Plan)
		if prior.State != state || prior.PlanSHA256 != record.PlanSHA256 || !bytes.Equal(priorRaw, raw) {
			return errors.New("原加固终态与本次核对冲突，未覆盖")
		}
		return nil
	}
	if len(inventory.Records) >= hardeningJournalRecords {
		return errors.New("加固终态库存已满，保留原待恢复计划")
	}
	root, err := s.hardeningJournalArchiveRoot(false)
	if err != nil || root == nil {
		return errors.New("加固终态目录缺失或不可核对")
	}
	defer root.Close()
	name := plan.ID + ".json"
	if _, err = root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("加固终态原标识已占用，未覆盖")
	}
	encoded, err := hardeningJournalEncode(record)
	if err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(root.Name(), name), encoded, 0600); err != nil {
		return hardeningJournalError("终态持久化", err)
	}
	file, err := hardeningReadBackupLimit(root, name, filepath.Join(root.Name(), name), true, hardeningJournalBytes)
	if err != nil || !file.existed || file.mode != 0600 || !bytes.Equal(file.data, encoded) {
		return errors.New("原加固终态完整内容无法核对，保留待恢复计划")
	}
	return nil
}

func (s *Service) hardeningJournalPublishTerminal(plan hardeningJournalPlan, raw []byte, state, recoveryJob string) error {
	if err := s.hardeningJournalWriteTerminal(plan, raw, state, recoveryJob); err != nil {
		return err
	}
	return s.hardeningJournalRemoveExact(plan, raw)
}
