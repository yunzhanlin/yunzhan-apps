//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const wafBodyRetentionRecordLimit = 256 << 10
const wafBodyRetentionHistoryLimit = 16

type wafBodyRetentionIdentity struct {
	Archive     wafBodyLogArchive `json:"archive"`
	IndexSHA256 string            `json:"index_sha256"`
	Device      uint64            `json:"device"`
	Inode       uint64            `json:"inode"`
	MtimeNano   int64             `json:"mtime_nano"`
	UID         uint32            `json:"uid"`
	GID         uint32            `json:"gid"`
}

type wafBodyRetentionDeletePlan struct {
	ID         string                     `json:"id"`
	At         string                     `json:"at"`
	Revision   int64                      `json:"policy_revision"`
	Days       int                        `json:"days"`
	KeepLatest int                        `json:"keep_latest"`
	Inventory  []wafBodyRetentionIdentity `json:"inventory"`
	Selected   []string                   `json:"selected"`
}

type wafBodyRetentionOperation struct {
	Plan       wafBodyRetentionDeletePlan `json:"plan"`
	PlanSHA256 string                     `json:"plan_sha256"`
	State      string                     `json:"state"`
	Deleted    []string                   `json:"verified_deleted"`
}

type wafBodyRetentionRecord struct {
	Format    int                         `json:"format"`
	CheckedAt string                      `json:"checked_at"`
	Revision  int64                       `json:"policy_revision"`
	Operation *wafBodyRetentionOperation  `json:"operation,omitempty"`
	History   []wafBodyRetentionOperation `json:"history"`
}

func retentionPlanSHA(plan wafBodyRetentionDeletePlan) string {
	data, err := json.Marshal(plan)
	if err != nil {
		return ""
	}
	return core.Hash(string(data))
}

func validateWAFRetentionOperation(v wafBodyRetentionOperation) error {
	p := v.Plan
	if !core.ValidID(p.ID) || !validWAFRotationTime(p.At) || p.Revision < 0 || p.Days < 1 || p.Days > 365 || p.KeepLatest < 1 || p.KeepLatest > 7 || len(p.Inventory) < 2 || len(p.Inventory) > wafBodyLogArchiveLimit || len(p.Selected) < 1 || len(p.Selected) > len(p.Inventory)-p.KeepLatest || !wafLogDigestValid(v.PlanSHA256) || retentionPlanSHA(p) != v.PlanSHA256 || v.Deleted == nil || len(v.Deleted) > len(p.Selected) {
		return errors.New("自动清理计划身份、摘要或数量异常；证据保留")
	}
	if v.State != "deleting" && v.State != "completed" && v.State != "unknown" && v.State != "retained_unknown" || v.State == "completed" && len(v.Deleted) != len(p.Selected) {
		return errors.New("自动清理完成状态不可核实，未宣称成功")
	}
	seen := map[string]bool{}
	for _, item := range p.Inventory {
		if item.Archive.State != "completed" || !validWAFRotationArchive(&item.Archive) || seen[item.Archive.ID] || !wafLogDigestValid(item.IndexSHA256) || item.Device == 0 || item.Inode == 0 || item.MtimeNano <= 0 || item.UID != uint32(os.Geteuid()) {
			return errors.New("自动清理库存身份异常；未接管")
		}
		seen[item.Archive.ID] = true
	}
	selected := map[string]bool{}
	for _, id := range p.Selected {
		if !seen[id] || selected[id] {
			return errors.New("自动清理所选身份重复或不属于计划")
		}
		selected[id] = true
	}
	for i, id := range v.Deleted {
		if id != p.Selected[i] {
			return errors.New("自动清理进度不属于原计划顺序")
		}
	}
	at, _ := time.Parse(time.RFC3339, p.At)
	archives := []wafBodyLogArchive{}
	for _, item := range p.Inventory {
		archives = append(archives, item.Archive)
	}
	eligible, err := wafBodyRetentionPlan(&core.WAFBodyLogRetentionConfig{Enabled: true, ConfirmDelete: true, Days: p.Days, KeepLatest: p.KeepLatest}, archives, at)
	if err != nil || len(eligible) != len(p.Selected) {
		return errors.New("持久计划与原保留期策略不符")
	}
	for i, item := range eligible {
		if item.ID != p.Selected[i] {
			return errors.New("持久计划试图删除受保护快照")
		}
	}
	return nil
}

func validateWAFRetentionRecord(v wafBodyRetentionRecord) error {
	if v.Format != 1 || !validWAFRotationTime(v.CheckedAt) || v.Revision < 0 || v.History == nil || len(v.History) > wafBodyRetentionHistoryLimit {
		return errors.New("自动清理记录时间、格式或容量异常；未覆盖")
	}
	seen := map[string]bool{}
	if v.Operation != nil {
		if err := validateWAFRetentionOperation(*v.Operation); err != nil {
			return err
		}
		if v.Operation.Plan.At > v.CheckedAt {
			return errors.New("清理计划晚于检查时间；未覆盖异常记录")
		}
		seen[v.Operation.Plan.ID] = true
	}
	for _, item := range v.History {
		if err := validateWAFRetentionOperation(item); err != nil {
			return err
		}
		if seen[item.Plan.ID] || item.State != "completed" && item.State != "retained_unknown" {
			return errors.New("自动清理历史重复或未知结果尚未核对；未覆盖")
		}
		if item.Plan.At > v.CheckedAt {
			return errors.New("历史清理计划时间异常；证据保留")
		}
		seen[item.Plan.ID] = true
	}
	return nil
}

func (s *Service) wafBodyRetentionPath() string {
	return filepath.Join(s.Config.SecurityDir, "waf-body-log-retention.json")
}

func (s *Service) readWAFBodyRetentionRecord() (wafBodyRetentionRecord, string, error) {
	var out wafBodyRetentionRecord
	path := s.wafBodyRetentionPath()
	if err := ownedRuntimePath(path, false); err != nil {
		return out, "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > wafBodyRetentionRecordLimit || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return out, "", errors.New("自动清理记录不是私有有界单链接文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, wafBodyRetentionRecordLimit+1))
	if err != nil {
		return out, "", err
	}
	if err := validateWAFRotationJSONShape(data); err != nil {
		return out, "", err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, "", errors.New("自动清理记录不可解析；未修复或覆盖")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return out, "", errors.New("自动清理记录含额外内容")
	}
	if err := validateWAFRetentionRecord(out); err != nil {
		return out, "", err
	}
	return out, core.Hash(string(data)), nil
}

func (s *Service) writeWAFBodyRetentionRecord(v wafBodyRetentionRecord) error {
	if err := validateWAFRetentionRecord(v); err != nil {
		return err
	}
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, false); err != nil {
		return err
	}
	if _, _, err := s.readWAFBodyRetentionRecord(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil || len(data)+1 > wafBodyRetentionRecordLimit {
		return errors.New("自动清理记录超过固定容量；未丢弃证据")
	}
	return atomicWrite(s.wafBodyRetentionPath(), append(data, '\n'), 0600)
}

// Only old completed summaries may leave bounded history. Unknown operations
// retain their whole original plan and verified progress until explicit review.
func archiveWAFRetentionOperation(v *wafBodyRetentionRecord) error {
	if v.Operation == nil {
		return nil
	}
	if v.Operation.State != "completed" && v.Operation.State != "retained_unknown" {
		return errors.New("自动清理结果未知；不重复删除")
	}
	if len(v.History) == wafBodyRetentionHistoryLimit {
		at := -1
		for i, item := range v.History {
			if item.State == "completed" {
				at = i
				break
			}
		}
		if at < 0 {
			return errors.New("未知清理历史已达上限；原证据保留，未开始删除")
		}
		v.History = append(v.History[:at], v.History[at+1:]...)
	}
	v.History = append(v.History, *v.Operation)
	return nil
}
