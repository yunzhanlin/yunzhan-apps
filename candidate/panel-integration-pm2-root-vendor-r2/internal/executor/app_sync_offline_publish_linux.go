//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"

	"golang.org/x/sys/unix"
)

// Recovery cannot create another named .part while trying to retain the
// original .part. An O_TMPFILE inode is invisible until the fully written,
// fsynced receipt is linked, exclusively, under its one fixed name. Closing an
// interrupted unpublished inode leaves the original namespace unchanged.
// Unsupported filesystems/capabilities refuse; there is no named-file fallback.
// https://man7.org/linux/man-pages/man2/open.2.html
func publishUnpublishedOfflineReceipt(d *modulePrivateDirectory, receipt remoteUnpublishedRetention, authorize func() error) error {
	if authorize == nil || !d.current() {
		return errors.New("离线回执缺少当前独立停写授权")
	}
	if _, err := d.Lstat(remoteUnpublishedReceipt); !errors.Is(err, os.ErrNotExist) {
		return errors.New("原回执已存在或无法核对；离线恢复不得覆盖")
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil || int64(len(raw))+1 > remoteCopyRecordLimit {
		return errors.New("离线回执超过完整容量限制")
	}
	raw = append(raw, '\n')
	directory, err := d.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	held, heldErr := d.Stat(".")
	if err != nil || heldErr != nil || !os.SameFile(opened, held) || !d.current() {
		return errors.New("离线回执目录句柄不属于当前私有原目录")
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("当前文件系统不支持匿名原子回执；未创建有名片段或更改原数据")
	}
	f := os.NewFile(uintptr(fd), "anonymous-filesync-retention-receipt")
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return errors.New("离线匿名回执写入不完整；未公开回执")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode != unix.S_IFREG|0600 || stat.Uid != 0 || stat.Nlink != 0 || stat.Size != int64(len(raw)) {
		return errors.New("匿名离线回执身份异常；未公开回执")
	}
	if err := authorize(); err != nil {
		return err
	}
	if !d.current() {
		return errors.New("离线回执公开前原目录身份变化")
	}
	// linkat never replaces an existing name. AT_EMPTY_PATH deliberately uses
	// the held anonymous inode, without a procfs path or a symlink fallback.
	if err := unix.Linkat(fd, "", int(directory.Fd()), remoteUnpublishedReceipt, unix.AT_EMPTY_PATH); err != nil {
		return errors.New("匿名离线回执公开未确认；原目录和执行结果保留，禁止自动重试")
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	var observed remoteUnpublishedRetention
	actual, err := remoteCopyMetadata(d, remoteUnpublishedReceipt, &observed)
	if err != nil || string(actual) != string(raw) {
		return errors.New("已公开的离线原回执尚未完整核对；禁止视为未执行")
	}
	return nil
}

func (s *Service) retainUnpublishedOfflineCondition(c remoteUnpublishedOfflineCondition, authorize func() error) (remoteUnpublishedOfflineWitness, bool, error) {
	var empty remoteUnpublishedOfflineWitness
	if authorize == nil {
		return empty, false, errors.New("原片段保留缺少独立授权核对")
	}
	if err := authorize(); err != nil {
		return empty, false, err
	}
	witness, err := s.matchUnpublishedOfflineCondition(c)
	if err != nil || witness.State == "observed-original-retained-receipt" {
		return witness, false, err
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil || remoteUnpublishedOfflineCensus(all) != c.CensusSHA || all.UnpublishedBytes > remoteUnpublishedMaxMetadataBytes-remoteCopyRecordLimit {
		return empty, false, errors.New("全量原库存变化或离线回执余量不足")
	}
	var current remoteUnpublishedCopy
	for _, r := range all.Unpublished {
		if r.Snapshot.TargetID == c.Target && r.Snapshot.TransactionID == c.Transaction {
			current = r
		}
	}
	if current.SHA != c.SnapshotSHA || current.Retained != nil || len(current.Snapshot.Fragments) >= remoteUnpublishedMaxParts {
		return empty, false, errors.New("原片段状态或有界片段余量已变化")
	}
	d, err := s.remoteCopyDirectory(c.Target, c.Transaction, "", false)
	if err != nil {
		return empty, false, err
	}
	defer d.Close()
	if err := remoteCopyFreeSpace(d, remoteCopyRecordLimit); err != nil {
		return empty, false, err
	}
	receipt := remoteUnpublishedRetention{Format: 1, Version: appcatalog.FilesSyncUnpublishedRetentionVersion, Snapshot: current.Snapshot, SnapshotSHA: current.SHA, ReviewedSpecSHA: c.ConfigSpecSHA, ReviewedRevision: c.Revision, RetainedAt: core.Now()}
	check := func() error {
		if err := authorize(); err != nil {
			return err
		}
		last, err := s.matchUnpublishedOfflineCondition(c)
		if err != nil || last.State != "original-unpublished" {
			return errors.New("离线公开前完整原条件变化；未公开新回执")
		}
		return nil
	}
	if err := publishUnpublishedOfflineReceipt(d, receipt, check); err != nil {
		return empty, false, err
	}
	witness, err = s.matchUnpublishedOfflineCondition(c)
	if err != nil || witness.State != "observed-original-retained-receipt" {
		return empty, true, errors.New("原回执已执行但完整结果尚未核对；不得自动重放")
	}
	return witness, true, nil
}

func readOfflineBounded(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("离线核对输入超过完整容量限制")
	}
	return raw, nil
}
