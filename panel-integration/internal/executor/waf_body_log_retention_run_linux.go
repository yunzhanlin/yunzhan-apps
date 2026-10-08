//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"time"
)

func (s *Service) runWAFBodyRetentionLocked(ctx context.Context, now time.Time, lock *os.File, cfg core.WAFConfig, checkpoint func(string) error) (wafBodyRetentionRecord, error) {
	var out wafBodyRetentionRecord
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := s.verifyWAFHealthLock(lock); err != nil {
		return out, err
	}
	if err := core.ValidateWAFBodyLogRotationSource(cfg); err != nil {
		return out, err
	}
	if cfg.BodyLogRetention == nil || !cfg.BodyLogRetention.Enabled {
		return out, nil
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("WAF 配置事务未完成；未自动清理")
	}
	rotation, _, err := s.readWAFBodyRotationRecord()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if err == nil && (rotation.State == "rotating" || rotation.State == "unknown") {
		return out, errors.New("快照轮转结果仍未知；未自动清理")
	}
	out, _, err = s.readWAFBodyRetentionRecord()
	if errors.Is(err, os.ErrNotExist) {
		out = wafBodyRetentionRecord{Format: 1, CheckedAt: now.UTC().Format(time.RFC3339), Revision: cfg.Policy.Revision, History: []wafBodyRetentionOperation{}}
	} else if err != nil {
		return out, err
	}
	if out.Operation != nil && (out.Operation.State == "deleting" || out.Operation.State == "unknown") {
		return out, errors.New("自动清理结果未知；保留原计划，不自动重试删除")
	}
	checked, _ := time.Parse(time.RFC3339, out.CheckedAt)
	if checked.After(now.Add(time.Minute)) {
		return out, errors.New("自动清理时钟回退或记录异常；未覆盖")
	}
	inventory, err := s.wafBodyRetentionInventory(ctx)
	if err != nil {
		return out, err
	}
	archives := []wafBodyLogArchive{}
	for _, item := range inventory {
		archives = append(archives, item.Archive)
	}
	selected, err := wafBodyRetentionPlan(cfg.BodyLogRetention, archives, now)
	if err != nil {
		return out, err
	}
	out.CheckedAt, out.Revision = now.UTC().Format(time.RFC3339), cfg.Policy.Revision
	if len(selected) == 0 {
		return out, s.writeWAFBodyRetentionRecord(out)
	}
	if err := archiveWAFRetentionOperation(&out); err != nil {
		return out, err
	}
	plan := wafBodyRetentionDeletePlan{ID: core.ID(), At: out.CheckedAt, Revision: cfg.Policy.Revision, Days: cfg.BodyLogRetention.Days, KeepLatest: cfg.BodyLogRetention.KeepLatest, Inventory: inventory, Selected: []string{}}
	for _, item := range selected {
		plan.Selected = append(plan.Selected, item.ID)
	}
	out.Operation = &wafBodyRetentionOperation{Plan: plan, PlanSHA256: retentionPlanSHA(plan), State: "deleting", Deleted: []string{}}
	if err := s.writeWAFBodyRetentionRecord(out); err != nil {
		return out, err
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	unknown := func(cause error) (wafBodyRetentionRecord, error) {
		out.Operation.State = "unknown"
		return out, errors.Join(cause, s.writeWAFBodyRetentionRecord(out))
	}
	if err := mark("retention-intent-durable"); err != nil {
		return unknown(err)
	}
	for _, entry := range selected {
		actual, err := s.wafBodyRetentionInventory(ctx)
		if err != nil || !retentionInventoryMatches(actual, plan, out.Operation.Deleted) {
			return unknown(errors.New("删除前快照库存与持久计划不符；未继续删除"))
		}
		if err := s.removeWAFBodyLogArchiveLockedAt(ctx, lock, entry.ID, entry.SHA256, mark); err != nil {
			return unknown(err)
		}
		if err := mark("retention-snapshot-removed"); err != nil {
			return unknown(err)
		}
		done := append(append([]string{}, out.Operation.Deleted...), entry.ID)
		actual, err = s.wafBodyRetentionInventory(ctx)
		if err != nil || !retentionInventoryMatches(actual, plan, done) {
			return unknown(errors.New("删除后原快照库存核对失败；未标成成功"))
		}
		out.Operation.Deleted = done
		if err := s.writeWAFBodyRetentionRecord(out); err != nil {
			return out, err
		}
		if err := mark("retention-progress-durable"); err != nil {
			return unknown(err)
		}
	}
	out.Operation.State = "completed"
	return out, s.writeWAFBodyRetentionRecord(out)
}

// Explicit review preserves the entire uncertain plan and partial progress.
// It neither resumes that plan nor declares absent snapshots deleted correctly.
func (s *Service) retainWAFBodyRetentionOutcome(ctx context.Context, sha string, now time.Time) (wafBodyRetentionRecord, error) {
	var out wafBodyRetentionRecord
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !wafLogDigestValid(sha) {
		return out, errors.New("自动清理记录摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return out, err
	}
	defer lock.Close()
	out, actual, err := s.readWAFBodyRetentionRecord()
	if err != nil {
		return out, err
	}
	if sha != actual || out.Operation == nil || out.Operation.State != "deleting" && out.Operation.State != "unknown" {
		return out, errors.New("自动清理记录已变化或并非未知结果；未接管")
	}
	checked, _ := time.Parse(time.RFC3339, out.CheckedAt)
	if checked.After(now) {
		return out, errors.New("清理核对时钟回退；保留原未知记录")
	}
	out.Operation.State = "retained_unknown"
	out.CheckedAt = now.UTC().Format(time.RFC3339)
	return out, s.writeWAFBodyRetentionRecord(out)
}
