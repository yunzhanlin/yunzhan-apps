//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type apacheCCArchiveSnapshot struct {
	Format             int                            `json:"format"`
	ID                 string                         `json:"id"`
	Files              map[string]apacheCCArchiveFile `json:"files"`
	SourceIdentityOnly bool                           `json:"source_identity_only"`
}

type apacheCCArchiveRetained struct {
	Format                 int                     `json:"format"`
	ID                     string                  `json:"id"`
	ReceiptID              string                  `json:"receipt_id"`
	At                     string                  `json:"at"`
	Outcome                string                  `json:"outcome"`
	Snapshot               apacheCCArchiveSnapshot `json:"snapshot"`
	SnapshotSHA            string                  `json:"snapshot_sha256"`
	IntentFile             apacheCCArchiveFile     `json:"retention_intent"`
	Archive                *apacheCCArchiveFile    `json:"archive,omitempty"`
	Source                 *apacheCCArchiveFile    `json:"preserved_source,omitempty"`
	Current                apacheCCArchiveFile     `json:"original_current_log"`
	NoReplay               bool                    `json:"no_replay"`
	NoExchange             bool                    `json:"no_name_exchange"`
	CurrentUntouched       bool                    `json:"current_log_untouched"`
	OriginalOutcomeUnknown bool                    `json:"original_outcome_unknown"`
}

type apacheCCArchiveRetainIntent struct {
	Format      int                     `json:"format"`
	ID          string                  `json:"id"`
	ReceiptID   string                  `json:"receipt_id"`
	At          string                  `json:"at"`
	Snapshot    apacheCCArchiveSnapshot `json:"snapshot"`
	SnapshotSHA string                  `json:"snapshot_sha256"`
	Current     apacheCCArchiveFile     `json:"original_current_log"`
}

func apacheCCArchiveRetentionName(name string) bool {
	id, ok := strings.CutPrefix(name, "retain-")
	if !ok {
		return false
	}
	id, ok = strings.CutSuffix(id, ".json")
	return ok && core.ValidID(id)
}

func apacheCCArchiveRetentionIntentName(name string) bool {
	id, ok := strings.CutPrefix(name, "retain-intent-")
	if !ok {
		return false
	}
	id, ok = strings.CutSuffix(id, ".json")
	return ok && core.ValidID(id)
}
func apacheCCArchiveRetentionFileName(name string) bool {
	return apacheCCArchiveRetentionName(name) || apacheCCArchiveRetentionIntentName(name)
}
func apacheCCArchiveRetentionID(name string) string {
	if apacheCCArchiveRetentionIntentName(name) {
		return strings.TrimSuffix(strings.TrimPrefix(name, "retain-intent-"), ".json")
	}
	if apacheCCArchiveRetentionName(name) {
		return strings.TrimSuffix(strings.TrimPrefix(name, "retain-"), ".json")
	}
	return ""
}

func apacheCCArchiveSnapshotSHA(v apacheCCArchiveSnapshot) string {
	raw, _ := json.Marshal(v)
	return core.Hash(string(raw))
}

func (s *Service) ccArchiveRecoveryOwner(info os.FileInfo, data bool) (int, int, error) {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("CC 原恢复文件身份不可核实")
	}
	if owner.Uid == uint32(os.Geteuid()) && owner.Gid == uint32(os.Getegid()) {
		return os.Geteuid(), os.Getegid(), nil
	}
	uid, gid, err := s.apacheCCArchiveWorker()
	if err != nil {
		return 0, 0, err
	}
	if data && owner.Uid == uint32(uid) && owner.Gid == uint32(gid) {
		return uid, gid, nil
	}
	return 0, 0, errors.New("CC 原恢复文件不属于固定原账户，未接管")
}

// Raw phase files can be empty or interrupted JSON. Their exact bytes remain
// evidence rather than programme/configuration authority. A pinned source fd is
// supplied only by the exclusive retention operation; HTTP cannot inject it.
func (s *Service) apacheCCRecoverySnapshot(ctx context.Context, id, exclude string, pinnedSource *os.File) (apacheCCArchiveSnapshot, error) {
	out := apacheCCArchiveSnapshot{Format: apacheCCArchiveFormat, ID: id, Files: map[string]apacheCCArchiveFile{}, SourceIdentityOnly: true}
	if !core.ValidID(id) || exclude != "" && !apacheCCArchiveRetentionName(exclude) {
		return out, errors.New("CC 原恢复标识无效")
	}
	dir, _, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		return out, err
	}
	entries, err := apacheCCArchiveDirectoryEntries(dir, apacheCCArchiveEntries)
	if err != nil {
		return out, err
	}
	retentions := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if name == exclude {
			continue
		}
		isData := name == "data.log"
		isSource := name == "next.log"
		retention := apacheCCArchiveRetentionFileName(name)
		if retention {
			retentions[apacheCCArchiveRetentionID(name)] = true
		}
		if !isData && !isSource && name != "intent.json" && name != "prepared.json" && name != "completed.json" && !retention || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return out, errors.New("CC 原恢复目录存在未知或链接条目，未忽略")
		}
		path := filepath.Join(dir, name)
		f := pinnedSource
		closeFile := false
		if !isSource || f == nil {
			f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if err != nil {
				return out, err
			}
			closeFile = true
		}
		inspect := func() (apacheCCArchiveFile, error) {
			info, err := f.Stat()
			if err != nil {
				return apacheCCArchiveFile{}, err
			}
			limit := int64(4096)
			if retention {
				limit = 16384
			}
			if isData {
				limit = apacheCCLogMaxBytes
			}
			if !isSource && info.Size() > limit {
				return apacheCCArchiveFile{}, errors.New("CC 原恢复文件超过固定容量")
			}
			uid, gid, err := s.ccArchiveRecoveryOwner(info, isSource)
			if err != nil {
				return apacheCCArchiveFile{}, err
			}
			if isSource {
				return apacheCCArchiveSourceIdentity(f, path, uid, gid)
			}
			return apacheCCArchiveInspect(ctx, f, path, uid, gid)
		}
		value, inspectErr := inspect()
		if closeFile {
			f.Close()
		}
		if inspectErr != nil {
			return out, inspectErr
		}
		if isData {
			if err := s.verifyApacheCCCopyProvenance(dir, id, value); err != nil {
				return out, err
			}
		}
		out.Files[name] = value
	}
	if len(retentions) > apacheCCArchiveRetentionAttempts {
		return out, errors.New("CC 原恢复残件超过固定上限，未丢弃证据")
	}
	return out, ctx.Err()
}

func (s *Service) validateApacheCCRetained(v apacheCCArchiveRetained, id, name string) error {
	if v.Format != apacheCCArchiveFormat || v.ID != id || !core.ValidID(v.ReceiptID) || name != "retain-"+v.ReceiptID+".json" || !validApacheNumericRotationTime(v.At) || v.Outcome != "unknown-retained" || v.Snapshot.Format != apacheCCArchiveFormat || !v.Snapshot.SourceIdentityOnly || v.Snapshot.ID != id || v.Snapshot.Files == nil || len(v.Snapshot.Files) > apacheCCArchiveEntries-2 || v.SnapshotSHA != apacheCCArchiveSnapshotSHA(v.Snapshot) || !v.NoReplay || !v.NoExchange || !v.CurrentUntouched || !v.OriginalOutcomeUnknown || !validApacheCCArchiveFile(v.Current) || !validApacheCCArchiveFile(v.IntentFile) || v.IntentFile.Bytes == 0 || v.IntentFile.Bytes > 16384 || v.IntentFile.UID != uint32(os.Geteuid()) || v.IntentFile.GID != uint32(os.Getegid()) {
		return errors.New("CC 原保留回执格式或原摘要不可核对")
	}
	uid, gid, err := s.apacheCCArchiveWorker()
	if err != nil {
		return err
	}
	if v.Current.UID != uint32(uid) || v.Current.GID != uint32(gid) {
		return errors.New("CC 保留回执中的原活动日志账户不一致")
	}
	for n, f := range v.Snapshot.Files {
		if n == name || n == "retain-intent-"+v.ReceiptID+".json" || !validApacheCCArchiveFile(f) {
			return errors.New("CC 保留回执存在循环或无效原证据")
		}
		if n == "next.log" {
			if f.Bytes != 0 || f.SHA256 != core.Hash("") {
				return errors.New("CC 来源身份快照不能冒充已封存内容")
			}
			if !((f.UID == uint32(uid) && f.GID == uint32(gid)) || (f.UID == uint32(os.Geteuid()) && f.GID == uint32(os.Getegid()))) {
				return errors.New("CC 原数据恢复账户不一致")
			}
		} else {
			limit := int64(4096)
			if apacheCCArchiveRetentionFileName(n) {
				limit = 16384
			} else if n == "data.log" {
				limit = apacheCCLogMaxBytes
			} else if n != "intent.json" && n != "prepared.json" && n != "completed.json" {
				return errors.New("CC 回执包含未知证据名")
			}
			if f.UID != uint32(os.Geteuid()) || f.GID != uint32(os.Getegid()) || f.Bytes > limit {
				return errors.New("CC 原阶段证据身份或容量不一致")
			}
		}
	}
	source, hasSource := v.Snapshot.Files["next.log"]
	if hasSource {
		source.UID, source.GID = uint32(os.Geteuid()), uint32(os.Getegid())
		if v.Source == nil || *v.Source != source {
			return errors.New("CC 原来源保留身份不一致")
		}
	} else if v.Source != nil {
		return errors.New("CC 缺失来源被冒充为已保留")
	}
	data, hasData := v.Snapshot.Files["data.log"]
	if !hasData {
		if v.Archive != nil {
			return errors.New("CC 原缺失数据被冒充为已保留")
		}
		return nil
	}
	data.UID, data.GID = uint32(os.Geteuid()), uint32(os.Getegid())
	if v.Archive == nil || *v.Archive != data {
		return errors.New("CC 已封存恢复数据与原快照身份不一致")
	}
	return nil
}

// At most one complete retention receipt may resolve an original operation.
// Older partial receipts remain opaque files in the new receipt's snapshot.
// Nothing marks the original archive successful or replays its exchange.
func (s *Service) readApacheCCArchiveRetained(ctx context.Context, id string, entries []os.DirEntry) (apacheCCArchiveRetained, string, bool, error) {
	var out apacheCCArchiveRetained
	dir, _, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		return out, "", false, err
	}
	digest := ""
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if !apacheCCArchiveRetentionName(name) {
			continue
		}
		var record apacheCCArchiveRetained
		sha, err := readApacheCCArchiveRecord(filepath.Join(dir, name), &record, 16384)
		if err != nil || s.validateApacheCCRetained(record, id, name) != nil {
			continue
		} // Preserve partial bytes; never adopt them.
		intentName := "retain-intent-" + record.ReceiptID + ".json"
		var original apacheCCArchiveRetainIntent
		if _, err := readApacheCCArchiveRecord(filepath.Join(dir, intentName), &original, 16384); err != nil {
			return out, "", false, err
		}
		if original.Format != apacheCCArchiveFormat || original.ID != id || original.ReceiptID != record.ReceiptID || !validApacheNumericRotationTime(original.At) || original.At > record.At || original.SnapshotSHA != record.SnapshotSHA || !reflect.DeepEqual(original.Snapshot, record.Snapshot) || original.Current != record.Current {
			return out, "", false, errors.New("CC 原保留意图与封存回执不一致")
		}
		observed, err := s.apacheCCRecoverySnapshot(ctx, id, name, nil)
		if err != nil {
			return out, "", false, err
		}
		projected := apacheCCArchiveSnapshot{Format: record.Snapshot.Format, ID: record.Snapshot.ID, Files: map[string]apacheCCArchiveFile{}, SourceIdentityOnly: true}
		for n, f := range record.Snapshot.Files {
			projected.Files[n] = f
		}
		if record.Archive != nil {
			projected.Files["data.log"] = *record.Archive
		}
		if record.Source != nil {
			projected.Files["next.log"] = *record.Source
		}
		projected.Files[intentName] = record.IntentFile
		if !reflect.DeepEqual(projected, observed) {
			return out, "", false, errors.New("CC 原保留证据在回执之后变化，未显示为正常库存")
		}
		if found {
			return out, "", false, errors.New("CC 原操作有冲突的完整保留回执，未自动选择")
		}
		out, digest, found = record, sha, true
	}
	return out, digest, found, nil
}

func (s *Service) retainApacheCCArchiveUnderLock(ctx context.Context, lock *os.File, id, expectedSHA string, checkpoint func(string) error) (apacheCCArchiveEntry, error) {
	var empty apacheCCArchiveEntry
	if !core.ValidID(id) || !wafLogDigestValid(expectedSHA) {
		return empty, errors.New("CC 原恢复标识或摘要无效")
	}
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return empty, err
	}
	entry, err := s.readApacheCCArchive(ctx, id)
	if err != nil {
		return empty, err
	}
	if entry.State == "retained-unknown" {
		if entry.Retained == nil || entry.Retained.SnapshotSHA != expectedSHA {
			return empty, errors.New("CC 原保留请求摘要不一致")
		}
		return entry, nil
	}
	if entry.State != "unknown" {
		return empty, errors.New("CC 所选原归档没有未知结果，不执行保留")
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return ctx.Err()
	}
	current, err := s.openApacheCCArchiveCurrent()
	if err != nil {
		return empty, err
	}
	defer current.Close()
	if err := unix.Flock(int(current.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return empty, errors.New("CC 当前日志正在写入，本次保留未开始")
	}
	defer unix.Flock(int(current.Fd()), unix.LOCK_UN)
	uid, gid, err := s.apacheCCArchiveWorker()
	if err != nil {
		return empty, err
	}
	currentBefore, err := apacheCCArchiveInspect(ctx, current, s.systemPath(apacheCCLogPath), uid, gid)
	if err != nil {
		return empty, err
	}
	dir := filepath.Join(s.apacheCCArchiveDirectory(), id)
	dataPath := filepath.Join(dir, "next.log")
	data, err := os.OpenFile(dataPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	if data != nil {
		defer data.Close()
		if err := unix.Flock(int(data.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return empty, errors.New("CC 原恢复数据仍在写入，未保留或改变账户")
		}
		defer unix.Flock(int(data.Fd()), unix.LOCK_UN)
	}
	snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", data)
	if err != nil {
		return empty, err
	}
	_, hasData := snapshot.Files["next.log"]
	if (data != nil) != hasData {
		return empty, errors.New("CC 原恢复数据的存在状态在核对期间变化，未保留")
	}
	if apacheCCArchiveSnapshotSHA(snapshot) != expectedSHA {
		return empty, errors.New("CC 原恢复快照已变化，需重新只读核对；原文件未动")
	}
	attempts := map[string]bool{}
	for name := range snapshot.Files {
		if apacheCCArchiveRetentionFileName(name) {
			attempts[apacheCCArchiveRetentionID(name)] = true
		}
	}
	if len(attempts) >= apacheCCArchiveRetentionAttempts {
		return empty, errors.New("CC 原保留残件达到 8 份，未覆盖或删除原证据")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := mark("original-evidence-verified"); err != nil {
		return empty, err
	}
	receiptID := core.ID()
	intentName := "retain-intent-" + receiptID + ".json"
	original := apacheCCArchiveRetainIntent{Format: apacheCCArchiveFormat, ID: id, ReceiptID: receiptID, At: core.Now(), Snapshot: snapshot, SnapshotSHA: expectedSHA, Current: currentBefore}
	if err := apacheCCArchivePhase(dir, intentName, original); err != nil {
		return empty, err
	}
	intentPath := filepath.Join(dir, intentName)
	intentFD, err := os.OpenFile(intentPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	intentFile, err := apacheCCArchiveInspect(ctx, intentFD, intentPath, os.Geteuid(), os.Getegid())
	intentFD.Close()
	if err != nil {
		return empty, err
	}
	if err := mark("retention-intent-durable"); err != nil {
		return empty, err
	}
	var preservedSource *apacheCCArchiveFile
	if data != nil {
		if err := data.Chown(os.Geteuid(), os.Getegid()); err != nil {
			return empty, err
		}
		if err := data.Sync(); err != nil {
			return empty, err
		}
		value, err := apacheCCArchiveSourceIdentity(data, dataPath, os.Geteuid(), os.Getegid())
		if err != nil {
			return empty, err
		}
		wanted := snapshot.Files["next.log"]
		wanted.UID, wanted.GID = uint32(os.Geteuid()), uint32(os.Getegid())
		if value != wanted {
			return empty, errors.New("CC 原恢复数据封存后身份变化，结果仍未知")
		}
		preservedSource = &value
	}
	var archived *apacheCCArchiveFile
	if wanted, present := snapshot.Files["data.log"]; present {
		path := filepath.Join(dir, "data.log")
		fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return empty, err
		}
		syncErr := fd.Sync()
		value, inspectErr := apacheCCArchiveInspect(ctx, fd, path, os.Geteuid(), os.Getegid())
		fd.Close()
		if syncErr != nil || inspectErr != nil || value != wanted {
			return empty, errors.New("CC Root 独立副本的持久化或完整性未核实；保留原残件")
		}
		archived = &value
	}
	if err := apacheNumericLogSyncDirectory(dir); err != nil {
		return empty, err
	}
	if err := mark("original-data-sealed"); err != nil {
		return empty, err
	}
	currentAfter, err := apacheCCArchiveInspect(ctx, current, s.systemPath(apacheCCLogPath), uid, gid)
	if err != nil || currentAfter != currentBefore {
		return empty, errors.New("CC 当前日志在原证据保留期间变化，未确认结果")
	}
	name := "retain-" + receiptID + ".json"
	retained := apacheCCArchiveRetained{Format: apacheCCArchiveFormat, ID: id, ReceiptID: receiptID, At: core.Now(), Outcome: "unknown-retained", Snapshot: snapshot, SnapshotSHA: expectedSHA, IntentFile: intentFile, Archive: archived, Source: preservedSource, Current: currentBefore, NoReplay: true, NoExchange: true, CurrentUntouched: true, OriginalOutcomeUnknown: true}
	if err := s.validateApacheCCRetained(retained, id, name); err != nil {
		return empty, err
	}
	if err := apacheCCArchivePhase(dir, name, retained); err != nil {
		return empty, err
	}
	if err := mark("retained-receipt-durable"); err != nil {
		return empty, err
	}
	if data != nil {
		if err := unix.Flock(int(data.Fd()), unix.LOCK_UN); err != nil {
			return empty, err
		}
	}
	if err := unix.Flock(int(current.Fd()), unix.LOCK_UN); err != nil {
		return empty, err
	}
	return s.readApacheCCArchive(ctx, id)
}
