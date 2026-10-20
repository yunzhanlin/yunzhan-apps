//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
)

func intrusionOriginalRequestMatches(plan intrusionJournalPlan, action string, settings map[string]any) bool {
	if plan.Action != action {
		return false
	}
	if action == "update" || action == "uninstall" {
		return len(settings) == 0
	}
	wanted, err := intrusionSettings(settings)
	return err == nil && maps.Equal(wanted, plan.TargetSettings)
}

// Versioned original-job controller. Release and installed acceptance remain
// independent gates. No synthetic job, restart, package install or auto retry is
// allowed. A durable but unclosed unknown outcome requires explicit recovery.
func (s *Service) applyIntrusionOperation(ctx context.Context, settings map[string]any, action string, add func(string)) error {
	if action != "install" && action != "configure" && action != "update" && action != "uninstall" {
		return errors.New("入侵防护操作不是受支持的固定生命周期")
	}
	if (action == "update" || action == "uninstall") && len(settings) != 0 {
		return errors.New("入侵防护更新和卸载不能附带请求限额或默认值")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	id, err := intrusionOriginalJob(ctx)
	if err != nil {
		return err
	}
	lock, err := s.intrusionMutationLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return err
	}
	if previous, exists := inventory.Records[id]; exists {
		if !intrusionOriginalRequestMatches(previous.Plan, action, settings) || previous.State != "committed" {
			return errors.New("原入侵防护任务已绑定不同请求或已恢复闭合；未作为新任务重放")
		}
		pending, raw, readErr := s.intrusionJournalPending()
		if errors.Is(readErr, os.ErrNotExist) {
			add("原任务已有不可变已提交回执；未重放系统操作，当前健康状态仍须独立检查")
			return nil
		}
		if readErr != nil {
			return readErr
		}
		encoded, encodeErr := intrusionJournalEncode(previous.Plan)
		if encodeErr != nil || pending.ID != id || !bytes.Equal(raw, encoded) || previous.PlanSHA256 != hardeningJournalDigest(raw) {
			return errors.New("待恢复记录不属于该原已提交任务；未关闭或替换另一事务")
		}
		// Advance sees the immutable terminal and ONLY verifies current state
		// then closes its original pending record; no scalar/file replay.
		if err := s.intrusionJournalAdvance(ctx, lock, pending, raw, "committed", ""); err != nil {
			return err
		}
		add("已独立核对原提交终态并仅关闭原待恢复记录；未重放系统变更")
		return nil
	}
	plan, raw, err := s.intrusionPrepareOperation(ctx, lock, action, settings)
	if err != nil {
		return err
	}
	before, err := intrusionJournalBeforeSettings(plan)
	if err != nil {
		return err
	}
	if before["ban_time_minutes"] != plan.TargetSettings["ban_time_minutes"] {
		add("封禁时长变更作用于当前及后续使用默认时长的封禁；开始时间不重置，到期时间会随新策略改变")
	}
	if err := s.intrusionJournalAdvance(ctx, lock, plan, raw, "committed", ""); err != nil {
		return errors.Join(err, errors.New("原事务尚需核对；未自动重试或补偿，须按原任务和完整摘要显式恢复"))
	}
	add("已核对受管文件、实际限额、动作模板与当前内核范围，持久提交原事务并关闭待恢复记录")
	add("保留当前封禁与开始时间；未重启服务、重载 Jail、重建历史地址或更改 SSH 监听")
	return nil
}
