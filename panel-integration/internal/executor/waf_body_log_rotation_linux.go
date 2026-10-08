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
	"strings"
	"syscall"
	"time"
)

const wafBodyRotationRecordLimit = 64 << 10
const wafBodyRotationHistoryLimit = 16

type wafBodyRotationOutcome struct {
	ID      string             `json:"id"`
	At      string             `json:"at"`
	Outcome string             `json:"outcome"`
	Archive *wafBodyLogArchive `json:"archive,omitempty"`
}

type wafBodyRotationRecord struct {
	Format          int                      `json:"format"`
	ID              string                   `json:"id"`
	State           string                   `json:"state"`
	WindowStartedAt string                   `json:"window_started_at"`
	CheckedAt       string                   `json:"checked_at"`
	LastRotationAt  string                   `json:"last_rotation_at,omitempty"`
	Revision        int64                    `json:"policy_revision"`
	LogBytes        int64                    `json:"log_bytes"`
	ArchiveCount    int                      `json:"archive_count"`
	Archive         *wafBodyLogArchive       `json:"archive,omitempty"`
	ErrorCode       string                   `json:"error_code,omitempty"`
	History         []wafBodyRotationOutcome `json:"history"`
}

func (s *Service) wafBodyRotationPath() string {
	return filepath.Join(s.Config.SecurityDir, "waf-body-log-rotation.json")
}

func validWAFRotationTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

func validWAFRotationArchive(entry *wafBodyLogArchive) bool {
	if entry == nil {
		return true
	}
	return core.ValidID(entry.ID) && validWAFRotationTime(entry.CapturedAt) && entry.Bytes > 0 && entry.Bytes <= wafBodyLogLimit && wafLogDigestValid(entry.SHA256) && (entry.State == "copying" || entry.State == "prepared" || entry.State == "completed")
}

func validateWAFRotationRecord(v wafBodyRotationRecord) error {
	states := map[string]bool{"idle": true, "rotating": true, "completed": true, "blocked": true, "unknown": true, "retained_unknown": true}
	codes := map[string]bool{"": true, "archive_capacity": true, "history_capacity": true, "rotation_failed": true, "verification_failed": true}
	if v.Format != 1 || !core.ValidID(v.ID) || !states[v.State] || !codes[v.ErrorCode] || !validWAFRotationTime(v.WindowStartedAt) || !validWAFRotationTime(v.CheckedAt) || v.LastRotationAt != "" && !validWAFRotationTime(v.LastRotationAt) || v.Revision < 0 || v.LogBytes < 0 || v.LogBytes > wafBodyLogLimit || v.ArchiveCount < 0 || v.ArchiveCount > wafBodyLogArchiveLimit || !validWAFRotationArchive(v.Archive) || v.History == nil || len(v.History) > wafBodyRotationHistoryLimit {
		return errors.New("自动轮转记录身份、时间、状态或容量异常，证据保留且不覆盖")
	}
	if v.State == "completed" && (v.Archive == nil || v.Archive.State != "completed" || v.LastRotationAt == "") {
		return errors.New("自动轮转记录缺少已完成快照，未当成成功")
	}
	seen := map[string]bool{}
	for _, h := range v.History {
		if !core.ValidID(h.ID) || seen[h.ID] || !validWAFRotationTime(h.At) || h.Outcome != "completed" && h.Outcome != "unknown_retained" || !validWAFRotationArchive(h.Archive) || h.Outcome == "completed" && (h.Archive == nil || h.Archive.State != "completed") {
			return errors.New("自动轮转历史格式或归属异常，未自动清除")
		}
		seen[h.ID] = true
	}
	return nil
}

// Reject ambiguous duplicate keys and null (including nested values), rather
// than let encoding/json silently replace an earlier field or keep a zero.
func validateWAFRotationJSONShape(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("自动轮转记录嵌套过深")
		}
		tok, err := d.Token()
		if err != nil || tok == nil {
			return errors.New("自动轮转记录不接受 null 或不完整值")
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errors.New("自动轮转记录包含重复或无效字段")
					}
					seen[name] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("自动轮转记录结构异常")
			}
			end, err := d.Token()
			if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
				return errors.New("自动轮转记录结构不完整")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("自动轮转记录有额外内容")
	}
	return nil
}

func (s *Service) readWAFBodyRotationRecord() (wafBodyRotationRecord, string, error) {
	var out wafBodyRotationRecord
	path := s.wafBodyRotationPath()
	if err := ownedRuntimePath(path, false); err != nil {
		return out, "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > wafBodyRotationRecordLimit || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return out, "", errors.New("自动轮转记录不是私有有界普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, wafBodyRotationRecordLimit+1))
	if err != nil {
		return out, "", err
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
	if err := validateWAFRotationRecord(out); err != nil {
		return out, "", err
	}
	return out, core.Hash(string(data)), nil
}

func (s *Service) writeWAFBodyRotationRecord(v wafBodyRotationRecord) error {
	if err := validateWAFRotationRecord(v); err != nil {
		return err
	}
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, false); err != nil {
		return err
	}
	if _, _, err := s.readWAFBodyRotationRecord(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil || len(data)+1 > wafBodyRotationRecordLimit {
		return errors.New("自动轮转记录超过固定容量")
	}
	return atomicWrite(s.wafBodyRotationPath(), append(data, '\n'), 0600)
}

// Successful summaries are bounded; unknown outcomes are never silently
// dropped. Sixteen retained unknown outcomes require explicit operator review.
func appendWAFRotationOutcome(v *wafBodyRotationRecord, h wafBodyRotationOutcome) error {
	if len(v.History) == wafBodyRotationHistoryLimit {
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
func (s *Service) runWAFBodyRotationLocked(ctx context.Context, now time.Time, lock *os.File, cfg core.WAFConfig, rotate func(string) (wafBodyLogArchive, error)) (wafBodyRotationRecord, error) {
	var out wafBodyRotationRecord
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := s.verifyWAFHealthLock(lock); err != nil {
		return out, err
	}
	if err := core.ValidateWAFBodyLogRotationSource(cfg); err != nil {
		return out, err
	}
	if cfg.BodyLogRotation == nil || !cfg.BodyLogRotation.Enabled {
		return out, nil
	}
	retention, _, retentionErr := s.readWAFBodyRetentionRecord()
	if retentionErr != nil && !errors.Is(retentionErr, os.ErrNotExist) {
		return out, retentionErr
	}
	if retentionErr == nil && retention.Operation != nil && (retention.Operation.State == "deleting" || retention.Operation.State == "unknown") {
		return out, errors.New("自动清理结果未知；不开始新的日志轮转")
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("WAF 配置事务尚未完成，不执行自动轮转")
	}
	var err error
	out, _, err = s.readWAFBodyRotationRecord()
	if errors.Is(err, os.ErrNotExist) {
		out = wafBodyRotationRecord{Format: 1, ID: core.ID(), State: "idle", WindowStartedAt: now.UTC().Format(time.RFC3339), CheckedAt: now.UTC().Format(time.RFC3339), History: []wafBodyRotationOutcome{}}
	} else if err != nil {
		return out, err
	}
	if out.State == "rotating" || out.State == "unknown" {
		return out, errors.New("自动轮转存在未知结果，需按摘要保留后核对；不会再次截断")
	}
	start, _ := time.Parse(time.RFC3339, out.WindowStartedAt)
	checked, _ := time.Parse(time.RFC3339, out.CheckedAt)
	if start.After(now.Add(time.Minute)) || checked.After(now.Add(time.Minute)) {
		return out, errors.New("自动轮转时钟或持久记录异常，未覆盖")
	}
	f, err := s.openWAFBodyLog(false, false)
	if err != nil {
		return out, err
	}
	st, err := f.Stat()
	f.Close()
	if err != nil {
		return out, err
	}
	stages, err := s.wafBodyLogIndexStages(ctx)
	if err != nil || len(stages) != 0 {
		return out, errors.New("存在未知索引残件，不执行自动轮转")
	}
	pending, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil || len(pending) != 0 {
		return out, errors.New("日志恢复库存异常或未完成，不执行自动轮转")
	}
	archives, err := s.wafBodyLogArchives()
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
	due := st.Size() > 0 && (st.Size() >= int64(cfg.BodyLogRotation.RotateMiB)<<20 || now.Sub(start) >= time.Duration(cfg.BodyLogRotation.MaxAgeMinutes)*time.Minute)
	if !due {
		out.State = "idle"
		return out, s.writeWAFBodyRotationRecord(out)
	}
	if len(archives) >= wafBodyLogArchiveLimit {
		out.State = "blocked"
		out.ErrorCode = "archive_capacity"
		return out, s.writeWAFBodyRotationRecord(out)
	}
	room := len(out.History) < wafBodyRotationHistoryLimit
	for _, h := range out.History {
		room = room || h.Outcome == "completed"
	}
	if !room {
		out.State = "blocked"
		out.ErrorCode = "history_capacity"
		return out, s.writeWAFBodyRotationRecord(out)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.ID = core.ID()
	out.State = "rotating"
	out.Archive = nil
	if err := s.writeWAFBodyRotationRecord(out); err != nil {
		return out, err
	}
	entry, rotationErr := rotate(out.ID)
	if core.ValidID(entry.ID) {
		out.Archive = &entry
	}
	if rotationErr != nil {
		out.State = "unknown"
		out.ErrorCode = "rotation_failed"
		if err := s.writeWAFBodyRotationRecord(out); err != nil {
			return out, err
		}
		return out, rotationErr
	}
	verified, verifyErr := s.wafBodyLogArchives()
	// An index and equal file size alone do not prove snapshot bytes. Verify
	// every full digest again after the truncation primitive before recording
	// a completed automatic outcome.
	remaining, digestErr := s.wafBodyLogRecoveryEntries(ctx)
	found := false
	for _, v := range verified {
		if v == entry && v.State == "completed" {
			found = true
		}
	}
	if verifyErr != nil || digestErr != nil || len(remaining) != 0 || !found {
		out.State = "unknown"
		out.ErrorCode = "verification_failed"
		if err := s.writeWAFBodyRotationRecord(out); err != nil {
			return out, err
		}
		return out, errors.New("自动轮转后快照摘要或完成状态核对失败，未标成成功")
	}
	out.State = "completed"
	out.LastRotationAt = now.UTC().Format(time.RFC3339)
	out.WindowStartedAt = out.LastRotationAt
	out.ArchiveCount = len(verified)
	if err := appendWAFRotationOutcome(&out, wafBodyRotationOutcome{ID: out.ID, At: out.LastRotationAt, Outcome: "completed", Archive: &entry}); err != nil {
		return out, err
	}
	return out, s.writeWAFBodyRotationRecord(out)
}

func (s *Service) runWAFBodyLogRotationOnce(ctx context.Context, now time.Time) error {
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	if manifest.Version != "2.4.0" && manifest.Version != "2.5.0" || cfg.BodyLogRotation == nil || !cfg.BodyLogRotation.Enabled {
		return nil
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	// The policy may have changed while the first read was in progress.
	manifest, err = s.readSoftwareManifest("nginx-waf")
	if err != nil {
		return err
	}
	cfg, err = core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	if manifest.Version != "2.4.0" && manifest.Version != "2.5.0" || cfg.BodyLogRotation == nil || !cfg.BodyLogRotation.Enabled {
		return nil
	}
	_, err = s.runWAFBodyRotationLocked(ctx, now, lock, cfg, func(intent string) (wafBodyLogArchive, error) { return s.rotateWAFBodyLogWithIntent(ctx, lock, intent) })
	return err
}

func (s *Service) runWAFBodyLogRotationWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		cycle, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := s.runWAFBodyLogRotationOnce(cycle, time.Now().UTC()); err != nil && ctx.Err() == nil {
			// Do not overwrite durable evidence when a lock, source, clock or
			// archive check fails. The private service journal still records a
			// bounded diagnostic instead of silently swallowing every failure.
			log.Printf("WAF numerical log rotation cycle deferred; completion not claimed: %.512s", err.Error())
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
func (s *Service) retainWAFBodyRotationOutcome(ctx context.Context, sha string, now time.Time) (wafBodyRotationRecord, error) {
	var out wafBodyRotationRecord
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
	out, actual, err := s.readWAFBodyRotationRecord()
	if err != nil {
		return out, err
	}
	if sha != actual || out.State != "rotating" && out.State != "unknown" {
		return out, errors.New("自动轮转记录已变化或并非未知结果，未接管")
	}
	stages, err := s.wafBodyLogIndexStages(ctx)
	if err != nil || len(stages) != 0 {
		return out, errors.New("请先按原摘要保留索引残件，不会自动清除")
	}
	pending, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil || len(pending) != 0 {
		return out, errors.New("请先核对并保留具体日志恢复记录，不会重复轮转")
	}
	if err := appendWAFRotationOutcome(&out, wafBodyRotationOutcome{ID: out.ID, At: now.UTC().Format(time.RFC3339), Outcome: "unknown_retained", Archive: out.Archive}); err != nil {
		return out, err
	}
	out.State = "retained_unknown"
	out.CheckedAt = now.UTC().Format(time.RFC3339)
	out.WindowStartedAt = out.CheckedAt
	out.ErrorCode = ""
	return out, s.writeWAFBodyRotationRecord(out)
}

func wafBodyRotationStatusMessage(code string) string {
	return map[string]string{"archive_capacity": "快照已达 8 份；没有自动删除历史，请先导出并按摘要管理快照", "history_capacity": "未知轮转结果已达上限；证据保留，需核对", "rotation_failed": "轮转未确认完成；可能已有备份或截断，不会自动重复", "verification_failed": "轮转后摘要或完成索引核对失败，不宣称成功"}[strings.TrimSpace(code)]
}
