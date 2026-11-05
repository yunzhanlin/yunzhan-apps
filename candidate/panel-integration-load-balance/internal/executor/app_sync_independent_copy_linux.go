//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

const remoteCopyScope = "从已提交且完整核对的远端归档建立本机Root私有独立副本，不改远端、网站、原归档或检查点。副本不是远端硬链接；远端旧写句柄不能修改本机字节。每份最多两份8MiB原文件，全部连接合计128份、1GiB（包括中断片段），每份最多8次明确尝试。中断后只显式核对恢复；完整本机副本可离线确认，残片保留并创建新的私有尝试，不截断或覆盖。列表只核对元数据，选择后核验完整内容；下载须完整摘要一致。未提供整站快照或自动删除，也不防御同等Root权限对本机副本的主动修改。"

func remoteCopyAction(action string) bool {
	switch action {
	case "remote-copy-preview", "remote-copies", "copy-remote-backup", "recover-remote-copy", "verify-remote-copy", "retain-remote-copy":
		return true
	}
	return false
}
func (s *Service) remoteCopyInstalled() error {
	r, err := s.moduleInstalledRecord("files-sync")
	if err != nil || r["version"] != appcatalog.FilesSyncIndependentBackupVersion {
		return errors.New("请先通过签名应用商店将文件同步更新到2.0.0；旧包未获得独立备份能力")
	}
	return nil
}
func remoteCopySHA(f *os.File, info os.FileInfo, expected moduleFile, current func() bool) error {
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) || !moduleRecordInfo(opened, false, false) || opened.Size() != expected.Size {
		return errors.New("独立副本打开期间变化")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, expected.Size+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA || !programQueueSame(info, after) || !current() {
		return errors.New("独立副本完整摘要或原文件身份不符；保留原字节")
	}
	return nil
}
func (s *Service) verifyRemoteCopyAttempt(record remoteCopyRecord, attempt string) ([]remoteCopyFile, error) {
	v := record.Intent.Source.Snapshot
	d, err := s.remoteCopyDirectory(v.TargetID, v.TransactionID, attempt, false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var receipt remoteCopyAttempt
	if _, err = remoteCopyMetadata(d, "attempt.json", &receipt); err != nil || receipt.Format != 1 || receipt.ID != attempt || receipt.IntentSHA != record.SHA {
		return nil, errors.New("独立副本尝试原身份无法核对")
	}
	files := []remoteCopyFile{}
	for _, source := range v.Files {
		info, err := d.Lstat(source.Name)
		if err != nil {
			return nil, err
		}
		metadata, err := remoteCopyFileMetadata(info, source.Name, source.File.SHA)
		if err != nil || metadata.Bytes != source.File.Size {
			return nil, errors.New("独立副本仍有残片，不确认为完整")
		}
		f, err := d.OpenFile(source.Name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		err = remoteCopySHA(f, info, source.File, func() bool {
			visible, err := d.Lstat(source.Name)
			return err == nil && programQueueSame(info, visible) && d.current()
		})
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("独立副本读取失败或完整摘要不符")
		}
		files = append(files, metadata)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}
func (s *Service) verifyRemoteCopy(record remoteCopyRecord) error {
	if record.Result == nil {
		return errors.New("独立备份尚未确认完成，请显式核对恢复")
	}
	files, err := s.verifyRemoteCopyAttempt(record, record.Result.AttemptID)
	if err != nil || len(files) != len(record.Result.Files) {
		return errors.New("独立备份完整内容核验未通过，未生成下载")
	}
	for i := range files {
		if files[i] != record.Result.Files[i] {
			return errors.New("独立备份完成后原inode或字节身份变化")
		}
	}
	return nil
}
func (s *Service) finishRemoteCopy(record remoteCopyRecord, attempt string, files []remoteCopyFile) (remoteCopyRecord, error) {
	v := record.Intent.Source.Snapshot
	d, err := s.remoteCopyDirectory(v.TargetID, v.TransactionID, "", false)
	if err != nil {
		return record, err
	}
	defer d.Close()
	result := remoteCopyResult{Format: 1, IntentSHA: record.SHA, AttemptID: attempt, Files: files, CompletedAt: core.Now()}
	if _, err = remoteCopyPublish(d, "result.json", result); err != nil {
		return record, err
	}
	return s.readRemoteCopyRecord(v.TargetID, v.TransactionID)
}
func remoteCopyFreeSpace(d *modulePrivateDirectory, needed int64) error {
	f, err := d.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &st); err != nil || st.Bsize < 1 || st.Bavail > uint64(^uint64(0)>>1)/uint64(st.Bsize) || needed < 0 || uint64(needed)+(256<<20) > st.Bavail*uint64(st.Bsize) || !d.current() {
		return errors.New("本机独立备份安全余量不足或不能核对；原文件与片段保留")
	}
	return nil
}
func (s *Service) copyRemoteSourceFile(ctx context.Context, c *remoteSyncClient, source string, name string, expected moduleFile, owner uint32, d *modulePrivateDirectory) error {
	if ctx.Err() != nil || !d.current() {
		return errors.New("独立备份已停止或目录变化")
	}
	before, err := c.Lstat(source)
	if err != nil || !remoteBackupOwnedFile(before, owner) || before.Size() != expected.Size || uint32(before.Mode().Perm()) != expected.Mode {
		return errors.New("原远端归档文件身份改变，未复制")
	}
	reader, err := c.Open(source)
	if err != nil {
		return err
	}
	defer reader.Close()
	opened, err := reader.Stat()
	if err != nil || !remoteBackupOwnedFile(opened, owner) || opened.Size() != expected.Size || uint32(opened.Mode().Perm()) != expected.Mode {
		return errors.New("远端归档打开期间身份变化")
	}
	writer, err := d.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(writer, h), reader, expected.Size)
	var extra [1]byte
	extraN, extraErr := reader.Read(extra[:])
	syncErr := writer.Sync()
	closeErr := writer.Close()
	if copyErr != nil || extraN != 0 || extraErr != io.EOF || syncErr != nil || closeErr != nil || n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA || ctx.Err() != nil || !d.current() {
		return errors.New("远端读取或独立副本刷盘未通过；原片段保留，不覆盖重传")
	}
	return remoteCopySync(d)
}
func (s *Service) remoteCopyReport(cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	rows, total, err := s.allRemoteCopyRecords()
	if err != nil {
		return nil, err
	}
	selected := []map[string]any{}
	for _, r := range rows {
		if r.Intent.Source.Snapshot.TargetID == cfg.ID {
			selected = append(selected, remoteCopyPublic(r, cfg.Revision, false))
		}
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := min(in.Offset, len(selected))
	end := min(start+limit, len(selected))
	return map[string]any{"independent_backups": selected[start:end], "total": len(selected), "global_copies": len(rows), "retained_bytes": total, "record_limit": remoteCopyMaxRecords, "byte_limit": remoteCopyMaxBytes, "attempt_limit": remoteCopyMaxAttempts, "offset": in.Offset, "limit": limit, "remote_files_changed": false, "scope": remoteCopyScope}, nil
}
func (s *Service) moduleRemoteCopy(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := s.remoteCopyInstalled(); err != nil {
		return nil, err
	}
	if err := remoteCopyInput(action, in); err != nil {
		return nil, err
	}
	cfg, err := s.readRemoteConfig(in.RemoteTargetID)
	if err != nil || cfg.Revision != in.ExpectedRevision {
		return nil, errors.New("远端连接身份或修订改变；请重新核对")
	}
	if action == "remote-copies" {
		return s.remoteCopyReport(cfg, in)
	}
	if action == "verify-remote-copy" {
		r, err := s.readRemoteCopyRecord(cfg.ID, in.ResourceID)
		if err != nil {
			return nil, err
		}
		if err = s.verifyRemoteCopy(r); err != nil {
			return nil, err
		}
		return map[string]any{"independent_backup": remoteCopyPublic(r, cfg.Revision, true), "remote_files_changed": false, "scope": remoteCopyScope}, nil
	}
	if action == "retain-remote-copy" {
		return s.retainRemoteCopy(cfg, in)
	}
	if err = s.remoteBackupArchiveIdle(cfg, ""); err != nil {
		return nil, err
	}
	if pending, err := s.remoteCopyPending(cfg.ID, in.ResourceID); err != nil || pending {
		return nil, errors.New("另一独立备份待核对或库存异常，未创建新副本")
	}
	record, recordErr := s.readRemoteCopyRecord(cfg.ID, in.ResourceID)
	if recordErr == nil {
		if action == "remote-copy-preview" {
			return map[string]any{"independent_backup": remoteCopyPublic(record, cfg.Revision, false), "remote_files_changed": false, "scope": remoteCopyScope}, nil
		}
		if record.Retained != nil {
			return nil, errors.New("原独立备份仅保留未完成片段，未声明成功；不覆盖原目录")
		}
		expected := record.Intent.Source.SHA
		if action == "recover-remote-copy" {
			expected = remoteCopyStateSHA(record)
		}
		if expected != in.ExpectedSHA || record.Intent.Source.Snapshot.SpecSHA != cfg.SpecSHA {
			return nil, errors.New("独立备份原摘要或原连接身份改变，未接管")
		}
		if record.Result != nil {
			if err = s.verifyRemoteCopy(record); err != nil {
				return nil, err
			}
			return map[string]any{"independent_backup": remoteCopyPublic(record, cfg.Revision, true), "replayed": true, "remote_files_changed": false, "scope": remoteCopyScope}, nil
		}
		if action != "recover-remote-copy" {
			return nil, errors.New("原独立备份未完成；保留原意图并显式核对恢复，不重新提交")
		}
		for _, attempt := range record.Attempts {
			if files, err := s.verifyRemoteCopyAttempt(record, attempt); err == nil {
				record, err = s.finishRemoteCopy(record, attempt, files)
				if err != nil {
					return nil, err
				}
				return map[string]any{"independent_backup": remoteCopyPublic(record, cfg.Revision, true), "recovered": true, "used_existing_complete_attempt": true, "remote_connected": false, "remote_files_changed": false, "scope": remoteCopyScope}, nil
			}
		}
	} else if !errors.Is(recordErr, os.ErrNotExist) {
		return nil, recordErr
	} else if action == "recover-remote-copy" {
		return nil, errors.New("没有原独立备份意图，不猜测恢复或重传")
	}
	if !cfg.Enabled {
		return nil, errors.New("远端连接已停用；已有完整副本仍可离线核验和下载")
	}
	source, err := s.readRemoteBackupArchiveRecord(cfg.ID, in.ResourceID)
	if err != nil || source.State != "committed" || source.Snapshot.SpecSHA != cfg.SpecSHA || len(source.Snapshot.Files) == 0 {
		return nil, errors.New("须先核对已提交的原远端备份归档")
	}
	if action == "copy-remote-backup" && source.SHA != in.ExpectedSHA {
		return nil, errors.New("所选原归档摘要改变，未复制")
	}
	if recordErr == nil && source.SHA != record.Intent.Source.SHA {
		return nil, errors.New("原意图与当前归档不一致，保留全部片段")
	}
	rows, total, err := s.allRemoteCopyRecords()
	needed := remoteBackupSnapshotBytes(source.Snapshot)
	if err != nil || recordErr != nil && len(rows) >= remoteCopyMaxRecords || total > remoteCopyMaxBytes-needed || len(record.Attempts) >= remoteCopyMaxAttempts {
		return nil, errors.New("独立备份容量、尝试次数或库存不能接收完整副本；原片段保留")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	connection, err := s.dialRemoteSync(bounded, cfg)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	owner, err := remoteRoots(connection.client, cfg)
	if err != nil || owner != source.Snapshot.Owner {
		return nil, errors.New("远端归档原账户身份改变")
	}
	_, _, remote := remoteBackupArchivePaths(cfg, in.ResourceID)
	if err = remoteBackupSnapshotMatches(connection.client, cfg, remote, source); err != nil {
		return nil, err
	}
	if action == "remote-copy-preview" {
		row := remoteBackupArchivePublic(source, cfg.Revision)
		row["content_verified"] = true // The selected remote source was fully read above; no local copy is claimed.
		row["independent_copy_state"], row["source_snapshot_sha256"], row["source_content_verified"], row["local_copy_content_verified"] = "reviewed", source.SHA, true, false
		return map[string]any{"independent_backup": row, "remote_files_changed": false, "scope": remoteCopyScope}, nil
	}
	if recordErr != nil {
		base, err := s.remoteCopyDirectory(cfg.ID, "", "", true)
		if err != nil {
			return nil, err
		}
		if err = remoteCopyFreeSpace(base, needed); err != nil {
			base.Close()
			return nil, err
		}
		if _, err = base.Lstat(in.ResourceID); !errors.Is(err, os.ErrNotExist) {
			base.Close()
			return nil, errors.New("原独立备份目录已存在或不能核对，不接管")
		}
		base.Close()
		d, err := s.remoteCopyDirectory(cfg.ID, in.ResourceID, "", true)
		if err != nil {
			return nil, err
		}
		intent := remoteCopyIntent{Format: 1, Version: appcatalog.FilesSyncIndependentBackupVersion, Source: source, CreatedAt: core.Now()}
		_, err = remoteCopyPublish(d, "intent.json", intent)
		d.Close()
		if err != nil {
			return nil, err
		}
		record, err = s.readRemoteCopyRecord(cfg.ID, in.ResourceID)
		if err != nil {
			return nil, err
		}
	}
	attempt := core.ID()
	d, err := s.remoteCopyDirectory(cfg.ID, in.ResourceID, attempt, true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = remoteCopyFreeSpace(d, needed); err != nil {
		return nil, err
	}
	_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: record.SHA, CreatedAt: core.Now()})
	if err != nil {
		return nil, err
	}
	for _, f := range source.Snapshot.Files {
		if err = s.copyRemoteSourceFile(bounded, connection.client, path.Join(remote, f.Name), f.Name, f.File, owner, d); err != nil {
			return nil, err
		}
	}
	files, err := s.verifyRemoteCopyAttempt(record, attempt)
	if err != nil {
		return nil, err
	}
	record, err = s.finishRemoteCopy(record, attempt, files)
	if err != nil {
		return nil, err
	}
	return map[string]any{"independent_backup": remoteCopyPublic(record, cfg.Revision, true), "recovered": action == "recover-remote-copy", "remote_files_changed": false, "scope": remoteCopyScope}, nil
}
