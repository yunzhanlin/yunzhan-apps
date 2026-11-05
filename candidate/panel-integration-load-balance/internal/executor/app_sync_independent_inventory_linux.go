//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"reflect"
	"sort"
	"syscall"
	"time"
)

func validateRemoteCopyIntent(v remoteCopyIntent, target, transaction string) error {
	if v.Format != 1 || v.Version != appcatalog.FilesSyncIndependentBackupVersion || v.Source.State != "committed" || len(v.Source.Snapshot.Files) == 0 || validateRemoteBackupArchiveRecord(v.Source, target, transaction) != nil {
		return errors.New("独立备份原意图、固定版本或源归档身份损坏")
	}
	created, err := time.Parse(time.RFC3339, v.CreatedAt)
	sourceAt, sourceErr := time.Parse(time.RFC3339, v.Source.CompletedAt)
	if err != nil || sourceErr != nil || created.Before(sourceAt) {
		return errors.New("独立备份原时间不能核对")
	}
	return nil
}
func remoteCopyFileMetadata(info os.FileInfo, name, digest string) (remoteCopyFile, error) {
	if !moduleRecordInfo(info, false, false) || info.Size() < 0 || info.Size() > remoteCopyFileLimit {
		return remoteCopyFile{}, errors.New("独立副本不是Root私有、无硬链接的有界普通文件")
	}
	v := info.Sys().(*syscall.Stat_t)
	return remoteCopyFile{Name: name, SHA: digest, Bytes: info.Size(), Device: uint64(v.Dev), Inode: v.Ino, UID: v.Uid, GID: v.Gid, Mode: uint32(info.Mode().Perm())}, nil
}
func remoteCopyExpected(v remoteCopyIntent) map[string]moduleFile {
	out := map[string]moduleFile{}
	for _, f := range v.Source.Snapshot.Files {
		out[f.Name] = f.File
	}
	return out
}
func remoteCopyPartialMetadata(d *modulePrivateDirectory, name string) (int64, error) {
	info, err := d.Lstat(name)
	if err != nil || !moduleRecordInfo(info, false, false) || info.Size() > remoteCopyRecordLimit {
		return 0, errors.New("独立备份记录片段身份异常，未忽略")
	}
	return info.Size(), nil
}
func (s *Service) readRemoteCopyRecord(target, transaction string) (remoteCopyRecord, error) {
	var record remoteCopyRecord
	d, err := s.remoteCopyDirectory(target, transaction, "", false)
	if err != nil {
		return record, err
	}
	defer d.Close()
	raw, err := remoteCopyMetadata(d, "intent.json", &record.Intent)
	if err != nil {
		return record, errors.New("独立备份原意图缺失或未知，保留原目录，不当成新任务")
	}
	if err = validateRemoteCopyIntent(record.Intent, target, transaction); err != nil {
		return record, err
	}
	record.SHA = core.Hash(string(raw))
	entries, err := remoteCopyEntries(d, remoteCopyMaxAttempts+4)
	if err != nil {
		return record, err
	}
	hasAttempts := false
	for _, entry := range entries {
		switch entry.Name() {
		case "intent.json", "result.json", "retained.json":
		case "attempts":
			hasAttempts = true
		default:
			if !remoteCopyTemporary(entry.Name()) {
				return record, errors.New("独立备份含未知条目，未返回不完整库存")
			}
			if _, err = remoteCopyPartialMetadata(d, entry.Name()); err != nil {
				return record, err
			}
		}
	}
	attemptFiles := map[string]map[string]remoteCopyFile{}
	expected := remoteCopyExpected(record.Intent)
	if hasAttempts {
		attempts, err := s.remoteCopyDirectory(target, transaction, "", false)
		if err != nil {
			return record, err
		}
		if err = remoteCopyDescend(attempts, "attempts", false); err != nil {
			attempts.Close()
			return record, err
		}
		children, err := remoteCopyEntries(attempts, remoteCopyMaxAttempts)
		attempts.Close()
		if err != nil {
			return record, err
		}
		for _, child := range children {
			if !core.ValidID(child.Name()) {
				return record, errors.New("独立备份尝试目录含未知标识")
			}
			files, bytes, err := s.remoteCopyAttemptInventory(target, transaction, child.Name(), record, expected)
			if err != nil {
				return record, err
			}
			record.Bytes += bytes
			record.Attempts = append(record.Attempts, child.Name())
			attemptFiles[child.Name()] = files
		}
	}
	sort.Strings(record.Attempts)
	var result remoteCopyResult
	_, err = remoteCopyMetadata(d, "result.json", &result)
	if errors.Is(err, os.ErrNotExist) {
		return s.readRemoteCopyRetained(d, record, attemptFiles)
	}
	if err != nil {
		return record, err
	}
	created, _ := time.Parse(time.RFC3339, record.Intent.CreatedAt)
	finished, atErr := time.Parse(time.RFC3339, result.CompletedAt)
	if result.Format != 1 || result.IntentSHA != record.SHA || !core.ValidID(result.AttemptID) || atErr != nil || finished.Before(created) || len(result.Files) != len(expected) || len(attemptFiles[result.AttemptID]) != len(expected) {
		return record, errors.New("独立备份完成回执未绑定完整原意图和副本")
	}
	for i, f := range result.Files {
		wanted, ok := expected[f.Name]
		actual, exists := attemptFiles[result.AttemptID][f.Name]
		actual.SHA = f.SHA
		if !ok || !exists || f.SHA != wanted.SHA || f.Bytes != wanted.Size || f.Mode != 0600 || i > 0 && result.Files[i-1].Name >= f.Name || actual != f {
			return record, errors.New("独立备份完成回执中的文件身份改变")
		}
	}
	record.Result = &result
	if _, err := d.Lstat("retained.json"); !errors.Is(err, os.ErrNotExist) {
		return record, errors.New("独立备份不能同时声明完整成功和保留残片")
	}
	return record, nil
}
func (s *Service) readRemoteCopyRetained(d *modulePrivateDirectory, record remoteCopyRecord, attempts map[string]map[string]remoteCopyFile) (remoteCopyRecord, error) {
	var closed remoteCopyRetained
	_, err := remoteCopyMetadata(d, "retained.json", &closed)
	if errors.Is(err, os.ErrNotExist) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	created, _ := time.Parse(time.RFC3339, record.Intent.CreatedAt)
	finished, atErr := time.Parse(time.RFC3339, closed.RetainedAt)
	expected := map[string]remoteCopyFile{}
	for attempt, files := range attempts {
		for name, f := range files {
			f.Name = attempt + "/" + name
			expected[f.Name] = f
		}
	}
	if closed.Format != 1 || closed.IntentSHA != record.SHA || atErr != nil || finished.Before(created) || closed.Files == nil || len(closed.Files) != len(expected) {
		return record, errors.New("独立备份残片保留回执不完整")
	}
	for i, f := range closed.Files {
		original, ok := expected[f.Name]
		original.SHA = f.SHA
		if !ok || !coreSHA.MatchString(f.SHA) || f != original || i > 0 && closed.Files[i-1].Name >= f.Name {
			return record, errors.New("独立备份保留残片的原身份改变")
		}
	}
	record.Retained = &closed
	return record, nil
}
func (s *Service) remoteCopyAttemptInventory(target, transaction, attempt string, record remoteCopyRecord, expected map[string]moduleFile) (map[string]remoteCopyFile, int64, error) {
	files := map[string]remoteCopyFile{}
	var total int64
	d, err := s.remoteCopyDirectory(target, transaction, attempt, false)
	if err != nil {
		return nil, 0, err
	}
	defer d.Close()
	entries, err := remoteCopyEntries(d, remoteCopyMaxAttempts+3)
	if err != nil {
		return nil, 0, err
	}
	var metadata remoteCopyAttempt
	_, err = remoteCopyMetadata(d, "attempt.json", &metadata)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, 0, err
	}
	if !missing {
		created, _ := time.Parse(time.RFC3339, record.Intent.CreatedAt)
		at, atErr := time.Parse(time.RFC3339, metadata.CreatedAt)
		if metadata.Format != 1 || metadata.ID != attempt || metadata.IntentSHA != record.SHA || atErr != nil || at.Before(created) {
			return nil, 0, errors.New("独立副本尝试没有绑定原意图")
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "attempt.json" {
			continue
		}
		if remoteCopyTemporary(name) {
			if _, err := remoteCopyPartialMetadata(d, name); err != nil {
				return nil, 0, err
			}
			continue
		}
		wanted, ok := expected[name]
		if !ok || missing {
			return nil, 0, errors.New("独立副本尝试含未授权文件或缺少原意图")
		}
		info, err := d.Lstat(name)
		if err != nil {
			return nil, 0, err
		}
		f, err := remoteCopyFileMetadata(info, name, "")
		if err != nil || f.Bytes > wanted.Size {
			return nil, 0, errors.New("独立副本片段类型、身份或容量异常")
		}
		total += f.Bytes
		files[name] = f
	}
	return files, total, nil
}
func (s *Service) allRemoteCopyRecords() ([]remoteCopyRecord, int64, error) {
	d, err := s.remoteCopyDirectory("", "", "", false)
	if errors.Is(err, os.ErrNotExist) {
		return []remoteCopyRecord{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer d.Close()
	targets, err := remoteCopyEntries(d, 16)
	if err != nil {
		return nil, 0, err
	}
	rows := []remoteCopyRecord{}
	var total int64
	for _, entry := range targets {
		if !syncPlanID.MatchString(entry.Name()) {
			return nil, 0, errors.New("独立备份含未知连接目录")
		}
		dir, err := s.remoteCopyDirectory(entry.Name(), "", "", false)
		if err != nil {
			return nil, 0, err
		}
		children, err := remoteCopyEntries(dir, remoteCopyMaxRecords)
		dir.Close()
		if err != nil {
			return nil, 0, err
		}
		for _, child := range children {
			if !core.ValidID(child.Name()) || len(rows) >= remoteCopyMaxRecords {
				return nil, 0, errors.New("独立备份超出128份或含未知目录")
			}
			r, err := s.readRemoteCopyRecord(entry.Name(), child.Name())
			if err != nil {
				return nil, 0, err
			}
			if total > remoteCopyMaxBytes-r.Bytes {
				return nil, 0, errors.New("独立备份和原片段超过1GiB；未自动删除")
			}
			total += r.Bytes
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Intent.Source.Snapshot, rows[j].Intent.Source.Snapshot
		return a.TargetID < b.TargetID || a.TargetID == b.TargetID && a.TransactionID < b.TransactionID
	})
	return rows, total, nil
}
func (s *Service) remoteCopyPending(target, allowTransaction string) (bool, error) {
	rows, _, err := s.allRemoteCopyRecords()
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		v := r.Intent.Source.Snapshot
		if (target == "" || v.TargetID == target) && v.TransactionID != allowTransaction && r.Result == nil && r.Retained == nil {
			return true, nil
		}
	}
	return false, nil
}

// Each admitted attempt changes this revision token before any file bytes are
// created. A late recovery request cannot start another attempt using a stale
// observation. The original intent/source hashes keep their existing meaning.
func remoteCopyStateSHA(r remoteCopyRecord) string {
	value := struct {
		Intent   string              `json:"intent_sha256"`
		Attempts []string            `json:"attempts"`
		Bytes    int64               `json:"retained_bytes"`
		Result   *remoteCopyResult   `json:"result"`
		Retained *remoteCopyRetained `json:"retained"`
	}{r.SHA, r.Attempts, r.Bytes, r.Result, r.Retained}
	raw, _ := json.Marshal(value)
	return core.Hash(string(raw))
}
func remoteCopyPublic(r remoteCopyRecord, revision int64, verified bool) map[string]any {
	v := r.Intent.Source.Snapshot
	state, finished := "needs-review", ""
	if r.Result != nil {
		state, finished = "committed", r.Result.CompletedAt
	} else if r.Retained != nil {
		state, finished = "retained-incomplete", r.Retained.RetainedAt
	}
	files := []map[string]any{}
	for _, f := range v.Files {
		files = append(files, map[string]any{"name": f.Name, "bytes": f.File.Size, "sha256": f.File.SHA})
	}
	return map[string]any{"remote_target_id": v.TargetID, "backup_transaction_id": v.TransactionID, "revision": revision, "source_snapshot_sha256": r.Intent.Source.SHA, "copy_intent_sha256": r.SHA, "copy_state_sha256": remoteCopyStateSHA(r), "independent_copy_state": state, "copy_bytes": remoteBackupSnapshotBytes(v), "retained_bytes": r.Bytes, "retained_attempts": len(r.Attempts), "created_at": r.Intent.CreatedAt, "completed_at": finished, "content_verified": verified, "pending_recovery": r.Result == nil && r.Retained == nil, "files": files}
}

func remoteCopyInput(action string, in core.AppModuleInput) error {
	if !remoteCopyAction(action) {
		return errors.New("独立备份动作无效")
	}
	rest := in
	rest.RemoteTargetID, rest.ExpectedRevision = "", 0
	if !syncPlanID.MatchString(in.RemoteTargetID) || in.ExpectedRevision < 1 {
		return errors.New("请选择实际远端连接与当前修订")
	}
	if action == "remote-copies" {
		rest.Limit, rest.Offset = 0, 0
		if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > remoteCopyMaxRecords {
			return errors.New("独立副本分页超出1–32条、0–128起点范围")
		}
	} else {
		rest.ResourceID = ""
		if !core.ValidID(in.ResourceID) {
			return errors.New("请选择实际原归档事务")
		}
		if action == "copy-remote-backup" || action == "recover-remote-copy" || action == "retain-remote-copy" {
			rest.ExpectedSHA, rest.Confirm = "", ""
			prefix := "COPY BACKUP "
			if action == "recover-remote-copy" {
				prefix = "RECOVER COPY "
			} else if action == "retain-remote-copy" {
				prefix = "RETAIN COPY "
			}
			if !coreSHA.MatchString(in.ExpectedSHA) || in.Confirm != prefix+in.ResourceID {
				return errors.New("独立备份与恢复须核对原摘要并填写精确确认")
			}
		}
	}
	if !reflect.DeepEqual(rest, core.AppModuleInput{}) {
		return errors.New("独立备份只接受当前连接、修订、原事务、摘要与确认，不接受路径、凭据或同步策略")
	}
	return nil
}
