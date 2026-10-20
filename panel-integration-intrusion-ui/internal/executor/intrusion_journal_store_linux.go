//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const intrusionPendingName = "intrusion.pending.json"
const intrusionJournalDirectory = "intrusion-transactions"
const intrusionMutationLockName = "intrusion-configuration.lock"
const intrusionJournalRecords = 128

var intrusionJournalTemporary = regexp.MustCompile(`^\.intrusion-terminal-[a-f0-9]{32}\.tmp$`)

type intrusionJournalTerminal struct {
	Format        int                  `json:"format"`
	State         string               `json:"state"`
	PlanSHA256    string               `json:"plan_sha256"`
	Plan          intrusionJournalPlan `json:"plan"`
	FinishedAt    string               `json:"finished_at"`
	RecoveryJobID string               `json:"recovery_job_id"`
}

func intrusionJournalTerminalDecode(raw []byte, id string) (intrusionJournalTerminal, error) {
	var record intrusionJournalTerminal
	if len(raw) < 1 || len(raw) > intrusionJournalBytes || decodeProgramQueueJSON(raw, &record) != nil || record.Format != 1 || record.Plan.ID != id || (record.State != "committed" && record.State != "rolled_back") || !hardeningCanonicalTime(record.FinishedAt) || record.FinishedAt < record.Plan.StartedAt {
		return record, errors.New("入侵防护终态格式、原任务、状态或时间不可核对")
	}
	if record.RecoveryJobID != "" && (!core.ValidID(record.RecoveryJobID) || record.RecoveryJobID == id || record.State != "rolled_back") {
		return record, errors.New("入侵防护终态恢复任务身份冲突")
	}
	if err := intrusionJournalValidate(record.Plan); err != nil {
		return record, err
	}
	plan, err := intrusionJournalEncode(record.Plan)
	if err != nil || hardeningJournalDigest(plan) != record.PlanSHA256 {
		return record, errors.New("入侵防护终态不属于原完整计划摘要")
	}
	canonical, err := intrusionJournalEncode(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return record, errors.New("入侵防护终态不是原完整规范记录")
	}
	return record, nil
}

func (s *Service) intrusionJournalRoot() (*os.Root, error) {
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, false); err != nil {
		return nil, err
	}
	return s.softwareManifestDirectory()
}

func (s *Service) intrusionJournalPending() (intrusionJournalPlan, []byte, error) {
	var plan intrusionJournalPlan
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return plan, nil, err
	}
	defer root.Close()
	file, err := hardeningReadBackupLimit(root, intrusionPendingName, filepath.Join(s.Config.SecurityDir, intrusionPendingName), true, intrusionJournalBytes)
	if err != nil {
		return plan, nil, err
	}
	if !file.existed {
		return plan, nil, os.ErrNotExist
	}
	if file.mode != 0600 {
		return plan, nil, errors.New("入侵防护待恢复事务不是0600私有记录，未修复")
	}
	plan, err = intrusionJournalDecode(file.data)
	return plan, file.data, err
}

// Opening a lock never repairs an existing inode or chmods the shared security
// root. Its legitimate 0750/0755 mode must remain available to other modules.
func (s *Service) intrusionMutationLock() (*os.File, error) {
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	info, err := root.Lstat(intrusionMutationLockName)
	if errors.Is(err, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return nil, err
	} else if !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 {
		return nil, errors.New("入侵防护锁身份、链接数或权限异常，未修复")
	}
	f, err := root.OpenFile(intrusionMutationLockName, flags, 0600)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	visible, visibleErr := root.Lstat(intrusionMutationLockName)
	if err != nil || visibleErr != nil || !softwareManifestRecordInfo(opened) || opened.Mode().Perm() != 0600 || !os.SameFile(opened, visible) || (info != nil && !os.SameFile(info, opened)) || !s.softwareManifestAnchorCurrent(root) {
		f.Close()
		return nil, errors.New("入侵防护锁命名身份变化")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("另一个入侵防护变更尚未结束，未等待或重放")
	}
	return f, nil
}

func (s *Service) intrusionJournalRequireLock(f *os.File) error {
	if f == nil {
		return errors.New("入侵防护事务缺少原独占锁")
	}
	flags, flagErr := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if flagErr != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		return errors.New("入侵防护只读观察描述符不能转换为变更权限")
	}
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := f.Stat()
	visible, visibleErr := root.Lstat(intrusionMutationLockName)
	if err != nil || visibleErr != nil || !softwareManifestRecordInfo(opened) || opened.Mode().Perm() != 0600 || !os.SameFile(opened, visible) || !s.softwareManifestAnchorCurrent(root) {
		return errors.New("入侵防护事务独占锁命名身份变化")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("入侵防护事务未取得原命名独占锁")
	}
	return nil
}

func (s *Service) intrusionJournalArchiveRoot(create bool) (*os.Root, error) {
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(intrusionJournalDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, nil
		}
		if err = root.Mkdir(intrusionJournalDirectory, 0700); err != nil {
			return nil, err
		}
		if err = hardeningJournalSync(root); err != nil {
			return nil, err
		}
		info, err = root.Lstat(intrusionJournalDirectory)
	}
	if err != nil {
		return nil, err
	}
	if !hardeningJournalDirectoryInfo(info) {
		return nil, errors.New("入侵防护事务归档目录身份或权限异常，未修复")
	}
	child, err := root.OpenRoot(intrusionJournalDirectory)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !hardeningJournalDirectoryInfo(opened) || !s.softwareManifestAnchorCurrent(root) {
		child.Close()
		return nil, errors.New("入侵防护事务归档目录打开期间变化")
	}
	return child, nil
}

type intrusionJournalInventory struct {
	Records        map[string]intrusionJournalTerminal
	TemporaryFiles int
	Bytes          int64
}

// Unknown, partial and over-capacity evidence never becomes "not installed" or
// success. Private incomplete write temporaries are retained, never cleaned up.
func (s *Service) intrusionJournalInventoryRead() (intrusionJournalInventory, error) {
	out := intrusionJournalInventory{Records: map[string]intrusionJournalTerminal{}}
	root, err := s.intrusionJournalArchiveRoot(false)
	if err != nil || root == nil {
		return out, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return out, err
	}
	entries, err := dir.ReadDir(intrusionJournalRecords*2 + 1)
	dir.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > intrusionJournalRecords*2 {
		return out, errors.New("入侵防护完整事务库存超过固定容量")
	}
	for _, entry := range entries {
		name := entry.Name()
		if intrusionJournalTemporary.MatchString(name) {
			info, err := root.Lstat(name)
			if err != nil || !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > intrusionJournalBytes {
				return out, errors.New("入侵防护私有临时证据类型、身份或容量异常")
			}
			out.TemporaryFiles++
			out.Bytes += info.Size()
			if out.TemporaryFiles > intrusionJournalRecords {
				return out, errors.New("入侵防护临时证据库存已满，未删除证据")
			}
			continue
		}
		if len(name) != 37 || name[32:] != ".json" || !core.ValidID(name[:32]) {
			return out, errors.New("入侵防护事务库存含未知条目，未忽略或删除")
		}
		file, err := hardeningReadBackupLimit(root, name, filepath.Join(s.Config.SecurityDir, intrusionJournalDirectory, name), true, intrusionJournalBytes)
		if err != nil || !file.existed || file.mode != 0600 {
			return out, errors.New("入侵防护完整终态身份、权限或容量无法核对")
		}
		record, err := intrusionJournalTerminalDecode(file.data, name[:32])
		if err != nil {
			return out, err
		}
		out.Records[record.Plan.ID] = record
		out.Bytes += int64(len(file.data))
		if len(out.Records) > intrusionJournalRecords || out.Bytes > 16<<20 {
			return out, errors.New("入侵防护完整事务库存已满，未删除恢复证据")
		}
	}
	if out.Bytes > 16<<20 {
		return out, errors.New("入侵防护事务库存字节预算已满")
	}
	if err := s.intrusionJournalArchiveCurrent(root); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) intrusionJournalRequireClosed() error {
	_, _, err := s.intrusionJournalPending()
	if !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("存在未闭合的入侵防护事务；须按原任务和完整摘要显式恢复，未重放变更")
	}
	_, err = s.intrusionJournalInventoryRead()
	return err
}

// The original, exclusively created and fsynced pending record must be verified
// BEFORE the caller may write a Jail, reload anything or change kernel rules.
// Every preparation failure retains any partial evidence and forbids mutation.
func (s *Service) intrusionJournalPrepare(lock *os.File, plan intrusionJournalPlan) ([]byte, error) {
	if err := s.intrusionJournalRequireLock(lock); err != nil {
		return nil, err
	}
	if err := intrusionJournalValidate(plan); err != nil {
		return nil, err
	}
	if err := s.intrusionJournalRequireClosed(); err != nil {
		return nil, err
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return nil, err
	}
	if _, exists := inventory.Records[plan.ID]; exists {
		return nil, errors.New("入侵防护原任务已有完整终态，未重新准备或重放")
	}
	if len(inventory.Records) >= intrusionJournalRecords || inventory.Bytes > 16<<20-intrusionJournalBytes {
		return nil, errors.New("入侵防护恢复证据容量不足，未删除原记录")
	}
	archive, err := s.intrusionJournalArchiveRoot(true)
	if err != nil {
		return nil, err
	}
	archive.Close()
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := intrusionJournalEncode(plan)
	if err != nil {
		return nil, err
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return nil, errors.New("入侵防护准备根目录身份已变化")
	}
	f, err := root.OpenFile(intrusionPendingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = hardeningJournalSync(root); err != nil {
		return nil, err
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return nil, errors.New("入侵防护准备持久化后根目录身份变化，未执行系统变更")
	}
	got, again, err := s.intrusionJournalPending()
	if err != nil || got.ID != plan.ID || !bytes.Equal(raw, again) {
		return nil, errors.New("入侵防护原计划持久化后不能完整核对，未执行系统变更")
	}
	return raw, nil
}
