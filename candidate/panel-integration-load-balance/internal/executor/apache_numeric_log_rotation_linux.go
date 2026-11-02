//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const apacheNumericRotationRecordLimit = 64 << 10
const apacheNumericRotationHistoryLimit = 16

type apacheNumericRotationOutcome struct {
	ID      string                   `json:"id"`
	At      string                   `json:"at"`
	Outcome string                   `json:"outcome"`
	Archive *apacheNumericLogArchive `json:"archive,omitempty"`
}

type apacheNumericRotationRecord struct {
	Format          int                            `json:"format"`
	ConfigRevision  int64                          `json:"config_revision"`
	Policy          core.WAFBodyLogRotationConfig  `json:"policy"`
	ID              string                         `json:"id"`
	State           string                         `json:"state"`
	WindowStartedAt string                         `json:"window_started_at"`
	CheckedAt       string                         `json:"checked_at"`
	LastRotationAt  string                         `json:"last_rotation_at,omitempty"`
	Revision        int64                          `json:"policy_revision"`
	LogBytes        int64                          `json:"log_bytes"`
	ArchiveCount    int                            `json:"archive_count"`
	Archive         *apacheNumericLogArchive       `json:"archive,omitempty"`
	ErrorCode       string                         `json:"error_code,omitempty"`
	History         []apacheNumericRotationOutcome `json:"history"`
}

func (s *Service) apacheNumericRotationPath() string {
	return filepath.Join(s.moduleDir("apache-waf"), "numeric-log-automation.json")
}

func validApacheNumericRotationTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func validApacheNumericRotationArchive(entry *apacheNumericLogArchive) bool {
	if entry == nil {
		return true
	}
	return core.ValidID(entry.ID) && validApacheNumericRotationTime(entry.CapturedAt) && entry.Bytes > 0 && entry.Bytes <= apacheNumericLogLimit && wafLogDigestValid(entry.SHA256) && (entry.State == "copying" || entry.State == "prepared" || entry.State == "completed")
}

func validateApacheNumericRotationRecord(v apacheNumericRotationRecord) error {
	states := map[string]bool{"idle": true, "rotating": true, "completed": true, "blocked": true, "unknown": true, "retained_unknown": true}
	codes := map[string]bool{"": true, "archive_capacity": true, "history_capacity": true, "rotation_failed": true, "verification_failed": true}
	if v.ConfigRevision < 1 || v.ConfigRevision > 1000000000 || core.ValidateWAFBodyLogRotation(&v.Policy) != nil || v.Format != 1 || !core.ValidID(v.ID) || !states[v.State] || !codes[v.ErrorCode] || !validApacheNumericRotationTime(v.WindowStartedAt) || !validApacheNumericRotationTime(v.CheckedAt) || v.LastRotationAt != "" && !validApacheNumericRotationTime(v.LastRotationAt) || v.Revision < 0 || v.LogBytes < 0 || v.LogBytes > apacheNumericLogLimit || v.ArchiveCount < 0 || v.ArchiveCount > apacheNumericLogArchiveLimit || !validApacheNumericRotationArchive(v.Archive) || v.History == nil || len(v.History) > apacheNumericRotationHistoryLimit {
		return errors.New("自动轮转记录身份、时间、状态或容量异常，证据保留且不覆盖")
	}
	if v.State == "completed" && (v.Archive == nil || v.Archive.State != "completed" || v.LastRotationAt == "") {
		return errors.New("自动轮转记录缺少已完成快照，未当成成功")
	}
	seen := map[string]bool{}
	for _, h := range v.History {
		if !core.ValidID(h.ID) || seen[h.ID] || !validApacheNumericRotationTime(h.At) || h.Outcome != "completed" && h.Outcome != "unknown_retained" || !validApacheNumericRotationArchive(h.Archive) || h.Outcome == "completed" && (h.Archive == nil || h.Archive.State != "completed") {
			return errors.New("自动轮转历史格式或归属异常，未自动清除")
		}
		seen[h.ID] = true
	}
	return nil
}

func (s *Service) readApacheNumericRotationRecord() (apacheNumericRotationRecord, string, error) {
	var out apacheNumericRotationRecord
	path := s.apacheNumericRotationPath()
	if err := ownedRuntimePath(path, false); err != nil {
		return out, "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > apacheNumericRotationRecordLimit || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return out, "", errors.New("自动轮转记录不是私有有界普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, apacheNumericRotationRecordLimit+1))
	if err != nil {
		return out, "", err
	}
	after, statErr := f.Stat()
	named, nameErr := os.Lstat(path)
	if len(data) > apacheNumericRotationRecordLimit || statErr != nil || nameErr != nil || !apacheBodyEventsSameFile(st, after) || !apacheBodyEventsSameFile(after, named) {
		return out, "", errors.New("Apache 自动轮转记录在读取期间变化，未采用部分或旧记录")
	}
	if err := validateWAFRotationJSONShape(data); err != nil {
		return out, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, "", errors.New("自动轮转记录不可解析，未覆盖")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return out, "", errors.New("自动轮转记录有额外内容，未覆盖")
	}
	if err := validateApacheNumericRotationRecord(out); err != nil {
		return out, "", err
	}
	return out, core.Hash(string(data)), nil
}

func (s *Service) writeApacheNumericRotationRecord(v apacheNumericRotationRecord) error {
	if err := validateApacheNumericRotationRecord(v); err != nil {
		return err
	}
	if err := s.wafOwnedDirectory(s.moduleDir("apache-waf"), false); err != nil {
		return err
	}
	if _, _, err := s.readApacheNumericRotationRecord(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil || len(data)+1 > apacheNumericRotationRecordLimit {
		return errors.New("自动轮转记录超过固定容量")
	}
	return atomicWrite(s.apacheNumericRotationPath(), append(data, '\n'), 0600)
}

// Successful summaries are bounded; unknown outcomes are never silently
// dropped. Sixteen retained unknown outcomes require explicit operator review.
func appendApacheNumericRotationOutcome(v *apacheNumericRotationRecord, h apacheNumericRotationOutcome) error {
	if len(v.History) == apacheNumericRotationHistoryLimit {
		at := -1
		for i, item := range v.History {
			if item.Outcome == "completed" {
				at = i
				break
			}
		}
		if at < 0 {
			return errors.New("自动轮转未知结果记录已达上限，未自动删除证据")
		}
		v.History = append(v.History[:at], v.History[at+1:]...)
	}
	v.History = append(v.History, h)
	return nil
}

// Internal test seam only: production passes the same guarded snapshot
// operation used by manual rotation, never a caller-selected path or callback.
func (s *Service) runApacheNumericRotationLocked(ctx context.Context, now time.Time, lock *os.File, cfg core.WAFConfig, rotate func(string) (apacheNumericLogArchive, error)) (apacheNumericRotationRecord, error) {
	var out apacheNumericRotationRecord
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return out, err
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("WAF 配置事务尚未完成，不执行自动轮转")
	}
	var err error
	out, _, err = s.readApacheNumericRotationRecord()
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !out.Policy.Enabled {
		return out, nil
	}
	if cfg.Body == nil || !core.ValidID(cfg.Body.EngineJobID) {
		return out, errors.New("Apache 自动轮转需要明确选择已验证的本机请求体引擎")
	}
	if out.State == "rotating" || out.State == "unknown" {
		return out, errors.New("自动轮转存在未知结果，需按摘要保留后核对；不会再次截断")
	}
	start, _ := time.Parse(time.RFC3339, out.WindowStartedAt)
	checked, _ := time.Parse(time.RFC3339, out.CheckedAt)
	if start.After(now.Add(time.Minute)) || checked.After(now.Add(time.Minute)) {
		return out, errors.New("自动轮转时钟或持久记录异常，未覆盖")
	}
	f, err := s.openApacheNumericLog(false)
	if err != nil {
		return out, err
	}
	st, err := f.Stat()
	f.Close()
	if err != nil {
		return out, err
	}
	stages, err := s.apacheNumericLogIndexStages(ctx)
	if err != nil || len(stages) != 0 {
		return out, errors.New("存在未知索引残件，不执行自动轮转")
	}
	pending, err := s.apacheNumericLogRecoveryEntries(ctx)
	if err != nil || len(pending) != 0 {
		return out, errors.New("日志恢复库存异常或未完成，不执行自动轮转")
	}
	archives, err := s.apacheNumericLogArchives()
	if err != nil {
		return out, err
	}
	for _, entry := range archives {
		if entry.State != "completed" {
			return out, errors.New("未知日志快照需人工核对，不自动删除或轮转")
		}
	}
	out.CheckedAt = now.UTC().Format(time.RFC3339)
	out.Revision = cfg.Policy.Revision
	out.LogBytes = st.Size()
	out.ArchiveCount = len(archives)
	out.ErrorCode = ""
	due := st.Size() > 0 && (st.Size() >= int64(out.Policy.RotateMiB)<<20 || now.Sub(start) >= time.Duration(out.Policy.MaxAgeMinutes)*time.Minute)
	if !due {
		out.State = "idle"
		return out, s.writeApacheNumericRotationRecord(out)
	}
	if len(archives) >= apacheNumericLogArchiveLimit {
		out.State = "blocked"
		out.ErrorCode = "archive_capacity"
		return out, s.writeApacheNumericRotationRecord(out)
	}
	room := len(out.History) < apacheNumericRotationHistoryLimit
	for _, h := range out.History {
		room = room || h.Outcome == "completed"
	}
	if !room {
		out.State = "blocked"
		out.ErrorCode = "history_capacity"
		return out, s.writeApacheNumericRotationRecord(out)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.ID = core.ID()
	out.State = "rotating"
	out.Archive = nil
	if err := s.writeApacheNumericRotationRecord(out); err != nil {
		return out, err
	}
	entry, rotationErr := rotate(out.ID)
	if rotationErr == errApacheNumericWriterBusy && entry == (apacheNumericLogArchive{}) {
		// The primitive proved exclusion failed before any snapshot write. This
		// is a known no-op, unlike every error after snapshot intent creation.
		// Keep the original window and history; the next minute is a new check.
		// Reuse the existing record schema so a normal rollback can still read it.
		out.State = "blocked"
		out.ErrorCode = ""
		if err := s.writeApacheNumericRotationRecord(out); err != nil {
			return out, err
		}
		return out, rotationErr
	}
	if core.ValidID(entry.ID) {
		out.Archive = &entry
	}
	if rotationErr != nil {
		out.State = "unknown"
		out.ErrorCode = "rotation_failed"
		if err := s.writeApacheNumericRotationRecord(out); err != nil {
			return out, err
		}
		return out, rotationErr
	}
	verified, verifyErr := s.apacheNumericLogArchives()
	// An index and equal file size alone do not prove snapshot bytes. Verify
	// every full digest again after the truncation primitive before recording
	// a completed automatic outcome.
	remaining, digestErr := s.apacheNumericLogRecoveryEntries(ctx)
	found := false
	for _, v := range verified {
		if v == entry && v.State == "completed" {
			found = true
		}
	}
	if verifyErr != nil || digestErr != nil || len(remaining) != 0 || !found {
		out.State = "unknown"
		out.ErrorCode = "verification_failed"
		if err := s.writeApacheNumericRotationRecord(out); err != nil {
			return out, err
		}
		return out, errors.New("自动轮转后快照摘要或完成状态核对失败，未标成成功")
	}
	out.State = "completed"
	out.LastRotationAt = now.UTC().Format(time.RFC3339)
	out.WindowStartedAt = out.LastRotationAt
	out.ArchiveCount = len(verified)
	if err := appendApacheNumericRotationOutcome(&out, apacheNumericRotationOutcome{ID: out.ID, At: out.LastRotationAt, Outcome: "completed", Archive: &entry}); err != nil {
		return out, err
	}
	return out, s.writeApacheNumericRotationRecord(out)
}

// The signed application and its engine are prerequisites. The coordinator is
// panel-core maintenance: no application/configuration migration or enablement
// occurs on a programme upgrade, and an absent policy creates no files.
func (s *Service) runApacheNumericLogRotationOnce(ctx context.Context, now time.Time) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, native, err := s.apacheNumericInstalledConfig()
	if err != nil {
		return err
	}
	if !native {
		return nil
	}
	logs := s.apacheNumericLogService()
	record, _, err := logs.readApacheNumericRotationRecord()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.Policy.Enabled {
		return nil
	}
	lock, err := logs.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	cfg, native, err := logs.apacheNumericInstalledConfig()
	if err != nil {
		return err
	}
	if !native {
		return errors.New("Apache 原签名安装版本已变化，未轮转")
	}
	record, _, err = logs.readApacheNumericRotationRecord()
	if err != nil {
		return err
	}
	if !record.Policy.Enabled {
		return nil
	}
	if err = verifyApacheNumericRotationEngine(ctx, cfg); err != nil {
		return err
	}
	if err = logs.verifyApacheWAFHealth(ctx, core.ApacheWAFNativeBodyVersion, core.WAFSettings(cfg)); err != nil {
		return err
	}
	_, err = logs.runApacheNumericRotationLocked(ctx, now, lock, cfg, func(intent string) (apacheNumericLogArchive, error) {
		return logs.rotateApacheNumericLogWithIntent(ctx, lock, intent)
	})
	return err
}

func (s *Service) runApacheNumericLogRotationWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		cycle, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := s.runApacheNumericLogRotationOnce(cycle, time.Now().UTC()); err != nil && ctx.Err() == nil {
			// Do not overwrite durable evidence when a lock, source, clock or
			// archive check fails. The private service journal still records a
			// bounded diagnostic instead of silently swallowing every failure.
			log.Printf("Apache numerical log rotation cycle deferred; completion not claimed: %.512s", err.Error())
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Acknowledge uncertainty, never complete/repeat a truncate. No live log,
// archive, unknown inode or configuration is removed by this operation.
func (s *Service) retainApacheNumericRotationOutcome(ctx context.Context, sha string, now time.Time) (apacheNumericRotationRecord, error) {
	var out apacheNumericRotationRecord
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !wafLogDigestValid(sha) {
		return out, errors.New("自动轮转记录摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return out, err
	}
	defer lock.Close()
	out, actual, err := s.readApacheNumericRotationRecord()
	if err != nil {
		return out, err
	}
	if sha != actual || out.State != "rotating" && out.State != "unknown" {
		return out, errors.New("自动轮转记录已变化或并非未知结果，未接管")
	}
	checked, _ := time.Parse(time.RFC3339, out.CheckedAt)
	start, _ := time.Parse(time.RFC3339, out.WindowStartedAt)
	if checked.After(now.Add(time.Minute)) || start.After(now.Add(time.Minute)) {
		return out, errors.New("Apache 自动轮转核对时钟异常，未覆盖原证据")
	}
	stages, err := s.apacheNumericLogIndexStages(ctx)
	if err != nil || len(stages) != 0 {
		return out, errors.New("请先按原摘要保留索引残件，不会自动清除")
	}
	pending, err := s.apacheNumericLogRecoveryEntries(ctx)
	if err != nil || len(pending) != 0 {
		return out, errors.New("请先核对并保留具体日志恢复记录，不会重复轮转")
	}
	if err := appendApacheNumericRotationOutcome(&out, apacheNumericRotationOutcome{ID: out.ID, At: now.UTC().Format(time.RFC3339), Outcome: "unknown_retained", Archive: out.Archive}); err != nil {
		return out, err
	}
	out.State = "retained_unknown"
	out.CheckedAt = now.UTC().Format(time.RFC3339)
	out.WindowStartedAt = out.CheckedAt
	out.ErrorCode = ""
	return out, s.writeApacheNumericRotationRecord(out)
}
