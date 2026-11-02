//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const apacheNumericLogLimit int64 = 32 << 20
const apacheNumericLogArchiveLimit = 8

// Only a failed nonblocking BSD flock can return this exact sentinel. At that
// point no snapshot intent, copy or truncation has begun. Every other failure
// remains an uncertain operation for the automatic coordinator.
var errApacheNumericWriterBusy = errors.New("Apache 数值日志正在写入，本次未开始快照或截断；下一次定时检查再尝试")

type apacheNumericLogArchive struct {
	ID         string `json:"id"`
	CapturedAt string `json:"captured_at"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	State      string `json:"state"`
}

func (s *Service) apacheNumericLogArchiveDirectory() string {
	return s.systemPath("/var/lib/panel-apache-body/archives")
}

// Reading an index is deliberately independent of the copy. A durable intent
// precedes creation of that copy, so power loss can leave a known missing or
// partial snapshot without making an unowned orphan look like panel history.
func (s *Service) readApacheNumericLogIndex(id string) (apacheNumericLogArchive, string, error) {
	var entry apacheNumericLogArchive
	if !core.ValidID(id) {
		return entry, "", errors.New("元数据备份标识无效")
	}
	index := filepath.Join(s.apacheNumericLogArchiveDirectory(), id+".json")
	if err := ownedRuntimePath(index, false); err != nil {
		return entry, "", err
	}
	f, err := os.OpenFile(index, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return entry, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1024 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return entry, "", errors.New("元数据备份索引权限或大小异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return entry, "", err
	}
	if err := validateWAFRotationJSONShape(data); err != nil {
		return entry, "", err
	}
	if err := apacheBodyDecodeJSON(data, &entry); err != nil {
		return entry, "", err
	}
	states := map[string]bool{"copying": true, "prepared": true, "completed": true, "retained": true, "retained-incomplete": true, "retained-missing": true, "removing": true}
	if entry.ID != id || entry.Bytes < 0 || entry.Bytes > apacheNumericLogLimit || !wafLogDigestValid(entry.SHA256) || !states[entry.State] || entry.Bytes == 0 && entry.State != "retained-incomplete" && entry.State != "removing" {
		return entry, "", errors.New("元数据备份索引无效")
	}
	if _, err := time.Parse(time.RFC3339, entry.CapturedAt); err != nil {
		return entry, "", errors.New("元数据备份时间无效")
	}
	hash := sha256.Sum256(data)
	return entry, hex.EncodeToString(hash[:]), nil
}

type apacheNumericLogRecovery struct {
	Archive         apacheNumericLogArchive `json:"archive"`
	IndexSHA        string                  `json:"index_sha256"`
	SnapshotSHA     string                  `json:"snapshot_sha256"`
	SnapshotBytes   int64                   `json:"snapshot_bytes"`
	SnapshotMissing bool                    `json:"snapshot_missing"`
}

func (s *Service) apacheNumericLogRecoveryEntries(ctx context.Context) ([]apacheNumericLogRecovery, error) {
	out := []apacheNumericLogRecovery{}
	dir := s.apacheNumericLogArchiveDirectory()
	if err := s.wafOwnedDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		return nil, errors.New("元数据备份目录权限异常")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) > apacheNumericLogArchiveLimit*2 {
		return nil, errors.New("元数据备份数量或目录异常")
	}
	ids := map[string]bool{}
	for _, file := range files {
		id, suffix, ok := strings.Cut(file.Name(), ".")
		if !ok || !core.ValidID(id) || (suffix != "log" && suffix != "json") || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("备份目录存在未知文件，未自动接管")
		}
		ids[id] = true
	}
	if len(ids) > apacheNumericLogArchiveLimit {
		return nil, errors.New("元数据快照标识超过固定数量上限")
	}
	for id := range ids {
		entry, indexSHA, err := s.readApacheNumericLogIndex(id)
		if err != nil {
			return nil, err
		}
		pending := entry.State == "copying" || entry.State == "prepared" || entry.State == "removing"
		item := apacheNumericLogRecovery{Archive: entry, IndexSHA: indexSHA}
		f, err := s.openApacheNumericLogArchive(id)
		if errors.Is(err, os.ErrNotExist) {
			if !pending && entry.State != "retained-missing" {
				return nil, errors.New("已完成或保留的快照缺失，未用其它恢复记录掩盖异常")
			}
			item.SnapshotMissing = true
		} else if err != nil {
			return nil, err
		} else {
			st, err := f.Stat()
			f.Close()
			if err != nil {
				return nil, err
			}
			item.SnapshotBytes = st.Size()
			item.SnapshotSHA, err = wafNativeFileSHA(ctx, filepath.Join(dir, id+".log"), apacheNumericLogLimit)
			if err != nil {
				return nil, err
			}
		}
		if !pending {
			if entry.State == "retained-missing" && !item.SnapshotMissing || entry.State != "retained-missing" && (item.SnapshotSHA != entry.SHA256 || item.SnapshotBytes != entry.Bytes) {
				return nil, errors.New("已完成或保留的快照摘要、大小或缺失状态变化，未接管")
			}
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Archive.ID < out[j].Archive.ID })
	return out, nil
}

// Retain evidence, do not finish an uncertain truncate or fabricate success.
// Explicit digest-bound recovery never writes/truncates the current log.
func (s *Service) retainApacheNumericLogSnapshot(ctx context.Context, selected apacheNumericLogRecovery) error {
	if !core.ValidID(selected.Archive.ID) || !wafLogDigestValid(selected.IndexSHA) || (!selected.SnapshotMissing && !wafLogDigestValid(selected.SnapshotSHA)) || selected.SnapshotMissing && selected.SnapshotSHA != "" {
		return errors.New("恢复记录身份或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	entries, err := s.apacheNumericLogRecoveryEntries(ctx)
	if err != nil {
		return err
	}
	for _, current := range entries {
		if current.Archive.ID != selected.Archive.ID {
			continue
		}
		if current.IndexSHA != selected.IndexSHA || current.SnapshotSHA != selected.SnapshotSHA || current.SnapshotMissing != selected.SnapshotMissing {
			return errors.New("恢复记录已变化，未接管或修改")
		}
		if current.Archive.State == "removing" {
			return errors.New("所选快照处于明确删除事务，请以原摘要重试删除；不会当作完整备份")
		}
		if !current.SnapshotMissing {
			if err := s.syncApacheNumericLogEvidence(ctx, filepath.Join(s.apacheNumericLogArchiveDirectory(), current.Archive.ID+".log"), current.SnapshotSHA); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Preserve the original intent and the observed copy before repairing
		// its index. A fixed quota prevents repeated failures from growing an
		// unbounded recovery history. No failed evidence is silently removed.
		directory := filepath.Join(s.moduleDir("apache-waf"), "body-log-recovery")
		if err := s.apacheNumericLogPrivateDirectory(directory, true); err != nil {
			return err
		}
		files, err := os.ReadDir(directory)
		if err != nil || len(files) >= 100 {
			return errors.New("日志恢复证据已达 100 份，请先人工归档；原日志未动")
		}
		if err := moduleWrite(filepath.Join(directory, core.ID()+".json"), map[string]any{"created_at": core.Now(), "observed": current, "current_log_untouched": true, "rotation_outcome": "unknown_not_marked_successful"}); err != nil {
			return err
		}
		next := current.Archive
		if current.SnapshotMissing {
			next.State = "retained-missing"
		} else {
			next.State = "retained"
			if current.SnapshotSHA != next.SHA256 || current.SnapshotBytes != next.Bytes {
				next.State = "retained-incomplete"
			}
			next.Bytes = current.SnapshotBytes
			next.SHA256 = current.SnapshotSHA
		}
		return s.writeApacheNumericLogIndex(ctx, next)
	}
	return errors.New("所选快照没有可核对的未完成恢复记录")
}

func (s *Service) apacheNumericLogArchives() ([]apacheNumericLogArchive, error) {
	entries := []apacheNumericLogArchive{}
	directory := s.apacheNumericLogArchiveDirectory()
	if err := s.wafOwnedDirectory(directory, false); errors.Is(err, os.ErrNotExist) {
		return entries, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Lstat(directory)
	if err != nil || st.Mode().Perm() != 0700 {
		return nil, errors.New("元数据备份目录权限异常")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) > apacheNumericLogArchiveLimit*2 {
		return nil, errors.New("元数据备份目录不可读取或数量超限")
	}
	ids := map[string]bool{}
	for _, file := range files {
		name := file.Name()
		id, suffix, ok := strings.Cut(name, ".")
		if !ok || !core.ValidID(id) || (suffix != "log" && suffix != "json") || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("元数据备份目录存在未知条目，未接管")
		}
		ids[id] = true
	}
	if len(ids) > apacheNumericLogArchiveLimit {
		return nil, errors.New("元数据快照标识超过固定数量上限")
	}
	for id := range ids {
		entry, _, err := s.readApacheNumericLogIndex(id)
		if err != nil {
			return nil, err
		}
		if entry.State == "copying" || entry.State == "removing" {
			return nil, errors.New("存在未完成日志复制或删除事务，请先核对恢复记录；当前日志未修改")
		}
		f, err := s.openApacheNumericLogArchive(id)
		if entry.State == "retained-missing" && errors.Is(err, os.ErrNotExist) {
			entries = append(entries, entry)
			continue
		}
		if entry.State == "retained-missing" && err == nil {
			f.Close()
			return nil, errors.New("已标记缺失的快照重新出现，未接管")
		}
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		f.Close()
		if err != nil || st.Size() != entry.Bytes {
			return nil, errors.New("元数据备份大小变化")
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CapturedAt == entries[j].CapturedAt {
			return entries[i].ID > entries[j].ID
		}
		return entries[i].CapturedAt > entries[j].CapturedAt
	})
	return entries, nil
}

func (s *Service) openApacheNumericLogArchive(id string) (*os.File, error) {
	if !core.ValidID(id) {
		return nil, errors.New("元数据备份标识无效")
	}
	directory := s.apacheNumericLogArchiveDirectory()
	if err := s.wafOwnedDirectory(directory, false); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, id+".log")
	if err := ownedRuntimePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > apacheNumericLogLimit || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, errors.New("元数据备份不是私有有界普通文件")
	}
	return f, nil
}

// Snapshot before truncation is durable and exclusive. Same-inode rotation
// does not reload/stop Apache or touch its ordinary access/error logs. A failed
// commit retains both snapshot and live data; archives are never summed as
// disjoint traffic windows, and an incomplete snapshot blocks further writes.
func (s *Service) rotateApacheNumericLog(ctx context.Context) (apacheNumericLogArchive, error) {
	var out apacheNumericLogArchive
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return out, err
	}
	defer lock.Close()
	return s.rotateApacheNumericLogUnderLock(ctx, lock)
}

// The scheduler and manual operation share the exact engine/config/source
// gates and snapshot primitive. Reusing an actual exclusive lock is required.
func (s *Service) rotateApacheNumericLogUnderLock(ctx context.Context, lock *os.File) (apacheNumericLogArchive, error) {
	return s.rotateApacheNumericLogWithIntent(ctx, lock, "")
}

// Only the automatic coordinator can supply its own durable intent identity.
// A manual HTTP call must never bypass an unknown automatic truncate result.
func (s *Service) rotateApacheNumericLogWithIntent(ctx context.Context, lock *os.File, intent string) (apacheNumericLogArchive, error) {
	var out apacheNumericLogArchive
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return out, err
	}
	if err := s.apacheNumericRotationFence(ctx, intent); err != nil {
		return out, err
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("Apache 有未完成配置事务，未轮转")
	}
	if stages, err := s.apacheNumericLogIndexStages(ctx); err != nil || len(stages) != 0 {
		return out, errors.New("Apache 存在未提交索引残件，先核对保留原证据")
	}
	if pending, err := s.apacheNumericLogRecoveryEntries(ctx); err != nil || len(pending) != 0 {
		return out, errors.New("Apache 上次日志维护结果仍未知，未重复截断")
	}
	installed, err := s.moduleInstalledRecord("apache-waf")
	if err != nil || installed["version"] != core.ApacheWAFNativeBodyVersion {
		return out, errors.New("手动日志轮转须有完整 Apache2.4.0 原生安装")
	}
	settings, ok := installed["settings"].(map[string]any)
	if !ok {
		return out, errors.New("Apache 原配置缺失，未采用默认值")
	}
	if err = s.verifyApacheWAFHealth(ctx, core.ApacheWAFNativeBodyVersion, settings); err != nil {
		return out, err
	}
	return s.snapshotAndTruncateApacheNumericLog(ctx)
}

// Internal filesystem primitive. HTTP can reach it only through the manifest,
// engine, configuration-plan and cross-process lock checks above.
func (s *Service) snapshotAndTruncateApacheNumericLog(ctx context.Context) (apacheNumericLogArchive, error) {
	return s.snapshotAndTruncateApacheNumericLogAt(ctx, nil)
}

// Checkpoints are internal fault-injection seams, never caller input or an
// environment switch in production. The ordinary entry point passes nil.
func (s *Service) snapshotAndTruncateApacheNumericLogAt(ctx context.Context, checkpoint func(string) error) (apacheNumericLogArchive, error) {
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	var out apacheNumericLogArchive
	archives, err := s.apacheNumericLogArchives()
	if err != nil {
		return out, err
	}
	if len(archives) >= apacheNumericLogArchiveLimit {
		return out, errors.New("元数据备份已达 8 份，未丢弃历史；请先导出并管理备份")
	}
	for _, archive := range archives {
		if archive.State == "prepared" {
			return out, errors.New("上次元数据轮转未确认完成，证据保留，请先核对")
		}
	}
	f, err := s.openApacheNumericLog(true)
	if err != nil {
		return out, err
	}
	defer f.Close()
	// ModSecurity v2 uses BSD flock, not the fcntl record lock used by Apache.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return out, errApacheNumericWriterBusy
		}
		return out, errors.New("Apache 数值日志写入锁无法核对，未开始快照或截断")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if st.Size() == 0 {
		return out, errors.New("当前元数据日志为空，未生成空备份")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	originalHash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(io.LimitReader(f, apacheNumericLogLimit+1), originalHash))
	scanner.Buffer(make([]byte, 512), 513)
	for scanner.Scan() {
		if _, ok := parseApacheBodyEvent(scanner.Bytes()); !ok {
			return out, errors.New("元数据日志存在异常内容，保留原文件且未轮转")
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
	}
	if err := scanner.Err(); err != nil {
		return out, errors.New("元数据日志内容超过固定行上限，未轮转")
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], st.Size()-1); err != nil || last[0] != '\n' {
		return out, errors.New("Apache 数值日志末行不完整，保留且未截断")
	}
	observed, err := f.Stat()
	if err != nil || !apacheBodyEventsSameFile(st, observed) {
		return out, errors.New("Apache 数值日志在校验期间变化，未截断")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	directory := s.apacheNumericLogArchiveDirectory()
	if err := s.apacheNumericLogPrivateDirectory(directory, true); err != nil {
		return out, err
	}
	out = apacheNumericLogArchive{ID: core.ID(), CapturedAt: core.Now(), Bytes: st.Size(), State: "copying", SHA256: hex.EncodeToString(originalHash.Sum(nil))}
	// Intent is durable BEFORE creating a potentially partial snapshot.
	if err := s.writeApacheNumericLogIndexAt(ctx, out, func(stage string) error { return mark("intent-" + stage) }); err != nil {
		return out, err
	}
	if err := mark("intent-durable"); err != nil {
		return out, err
	}
	archive, err := os.OpenFile(filepath.Join(directory, out.ID+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return out, err
	}
	if err := mark("snapshot-created"); err != nil {
		archive.Close()
		return out, err
	}
	hash := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(archive, hash), f, st.Size())
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n != st.Size() {
		return out, errors.New("元数据备份未完整持久化；保留原日志及失败证据，未截断")
	}
	if hex.EncodeToString(hash.Sum(nil)) != out.SHA256 {
		return out, errors.New("日志复制摘要与持久化意图不符，保留原日志及失败证据")
	}
	if err := mark("snapshot-durable"); err != nil {
		return out, err
	}
	out.State = "prepared"
	if err := s.writeApacheNumericLogIndexAt(ctx, out, func(stage string) error { return mark("prepared-" + stage) }); err != nil {
		return out, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return out, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return out, err
	}
	if err := mark("prepared-durable"); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// The path must still identify the descriptor; a substituted file is never
	// truncated. Worker ownership changes on USR1 are deliberately supported.
	current, err := os.Lstat(s.systemPath(apacheBodyMetadataLog))
	if err != nil || !apacheBodyEventsSameFile(st, current) {
		return out, errors.New("元数据日志路径在备份后变化，未截断")
	}
	if err := f.Truncate(0); err != nil {
		return out, err
	}
	if err := f.Sync(); err != nil {
		return out, err
	}
	if err := mark("truncate-durable"); err != nil {
		return out, err
	}
	out.State = "completed"
	if err := s.writeApacheNumericLogIndexAt(ctx, out, func(stage string) error { return mark("completed-" + stage) }); err != nil {
		return out, errors.New("元数据已备份并轮转，但完成索引写入失败；证据保留，请核对")
	}
	if err := mark("completed-durable"); err != nil {
		return out, err
	}
	return out, nil
}

// Only an explicitly selected, digest-bound private snapshot can be removed.
// No active log, website log, directory, wildcard or caller path is accepted.
func (s *Service) removeApacheNumericLogArchive(ctx context.Context, id, sha string) error {
	return s.removeApacheNumericLogArchiveAt(ctx, id, sha, nil)
}

func (s *Service) removeApacheNumericLogArchiveAt(ctx context.Context, id, sha string, checkpoint func(string) error) error {
	if !core.ValidID(id) || !wafLogDigestValid(sha) {
		return errors.New("元数据备份标识或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	return s.removeApacheNumericLogArchiveLockedAt(ctx, lock, id, sha, checkpoint)
}

// Automatic retention shares the actual exclusive configuration lock. Never
// recursively acquire it or accept a caller-supplied file path.
func (s *Service) removeApacheNumericLogArchiveLockedAt(ctx context.Context, lock *os.File, id, sha string, checkpoint func(string) error) error {
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return err
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	if !core.ValidID(id) || len(sha) != 64 || strings.Trim(sha, "0123456789abcdef") != "" {
		return errors.New("元数据备份标识或摘要无效")
	}
	if _, err := s.apacheNumericLogRecoveryEntries(ctx); err != nil {
		return err
	}
	entry, _, err := s.readApacheNumericLogIndex(id)
	if err != nil {
		return err
	}
	if entry.State == "copying" || entry.State == "prepared" {
		return errors.New("所选快照的原轮转结果尚未确认，请先按原摘要明确保留恢复证据，未删除")
	}
	if entry.State != "removing" {
		if _, err := s.apacheNumericLogArchives(); err != nil {
			return err
		}
	}
	if entry.SHA256 != sha {
		return errors.New("备份摘要与所选记录不符，未删除")
	}
	path := filepath.Join(s.apacheNumericLogArchiveDirectory(), id+".log")
	f, err := s.openApacheNumericLogArchive(id)
	missing := errors.Is(err, os.ErrNotExist) && (entry.State == "removing" || entry.State == "retained-missing")
	if err != nil && !missing {
		return err
	}
	if !missing {
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		actual, err := wafNativeFileSHA(ctx, path, apacheNumericLogLimit)
		if err != nil || actual != sha {
			return errors.New("备份实际摘要变化，未删除")
		}
		current, err := os.Lstat(path)
		if err != nil || !apacheBodyEventsSameFile(st, current) {
			return errors.New("备份路径发生替换，未删除")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entry.State = "removing"
	index := filepath.Join(s.apacheNumericLogArchiveDirectory(), id+".json")
	if err := s.writeApacheNumericLogIndexAt(ctx, entry, func(stage string) error { return mark("remove-" + stage) }); err != nil {
		return err
	}
	if err := mark("remove-intent-durable"); err != nil {
		return err
	}
	directory, err := os.Open(s.apacheNumericLogArchiveDirectory())
	if err != nil {
		return err
	}
	defer directory.Close()
	if !missing {
		if err := ctx.Err(); err != nil {
			return err
		}
		original, e := f.Stat()
		current, pathErr := os.Lstat(path)
		actual, digestErr := wafNativeFileSHA(ctx, path, apacheNumericLogLimit)
		if e != nil || pathErr != nil || digestErr != nil || !os.SameFile(original, current) || actual != sha || current.Size() != entry.Bytes {
			return errors.New("删除意图保存后快照身份或摘要变化；证据保留，未删除")
		}
		if err := siteLogExpiredOpenWriters(ctx, "/proc", []plannedSiteLog{{info: current}}); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	// Commit the data-file unlink before removing its durable intent.
	// A cold interruption can always retry this exact ID and digest.
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := mark("snapshot-unlink-durable"); err != nil {
		return err
	}
	currentIndex, _, err := s.readApacheNumericLogIndex(id)
	if err != nil || currentIndex != entry {
		return errors.New("删除意图索引发生变化；原证据保留，未清除索引")
	}
	if err := os.Remove(index); err != nil {
		return errors.New("所选快照已移除，但索引清理失败，请核对；不影响当前日志")
	}
	return directory.Sync()
}
