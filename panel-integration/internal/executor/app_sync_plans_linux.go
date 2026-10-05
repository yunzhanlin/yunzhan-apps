//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

var syncPlanID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

type moduleSyncPlan struct {
	ID             string   `json:"id"`
	SiteID         string   `json:"site_id"`
	TargetSiteID   string   `json:"target_site_id"`
	Excludes       []string `json:"excludes"`
	Interval       int      `json:"interval"`
	Enabled        bool     `json:"enabled"`
	Revision       int64    `json:"revision"`
	NextRunAt      string   `json:"next_run_at,omitempty"`
	LastState      string   `json:"last_state"`
	LastStartedAt  string   `json:"last_started_at,omitempty"`
	LastFinishedAt string   `json:"last_finished_at,omitempty"`
	LastError      string   `json:"last_error,omitempty"`
	FailureCount   int      `json:"failure_count"`
	Copied         int      `json:"copied_count"`
	Conflicts      int      `json:"conflicts_count"`
}

func (s *Service) syncPlanPath(id string) string {
	return filepath.Join(s.moduleDir("files-sync"), "plans", id+".json")
}
func validateSyncPlan(p moduleSyncPlan) error {
	if !syncPlanID.MatchString(p.ID) || !core.ValidID(p.SiteID) || !core.ValidID(p.TargetSiteID) || p.SiteID == p.TargetSiteID || p.Interval < 60 || p.Interval > 86400 || p.Revision < 1 || len(p.Excludes) > 64 {
		return errors.New("同步计划记录或参数无效")
	}
	for _, prefix := range p.Excludes {
		if !core.ValidFilePath(prefix, false) {
			return errors.New("排除路径无效")
		}
	}
	if p.Enabled {
		if _, err := time.Parse(time.RFC3339, p.NextRunAt); err != nil {
			return errors.New("计划执行时间无效")
		}
	}
	return nil
}
func (s *Service) readSyncPlans() ([]moduleSyncPlan, []map[string]string) {
	paths, _ := filepath.Glob(filepath.Join(s.moduleDir("files-sync"), "plans", "*.json"))
	sort.Strings(paths)
	plans := []moduleSyncPlan{}
	failures := []map[string]string{}
	if len(paths) > 32 {
		failures = append(failures, map[string]string{"error": "计划超过 32 个上限，只读取前 32 个"})
		paths = paths[:32]
	}
	for _, path := range paths {
		var plan moduleSyncPlan
		err := moduleRead(path, &plan)
		if err == nil {
			err = validateSyncPlan(plan)
		}
		if err == nil && filepath.Base(path) != plan.ID+".json" {
			err = errors.New("计划身份与文件名不匹配")
		}
		if err != nil {
			failures = append(failures, map[string]string{"id": filepath.Base(path), "error": err.Error()})
			continue
		}
		plans = append(plans, plan)
	}
	return plans, failures
}
func (s *Service) moduleSyncPlans(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if action == "run" {
		plans, failures := s.readSyncPlans()
		for i := range plans {
			if s.moduleAutoBlocked["files-sync/"+plans[i].ID] {
				plans[i].Enabled = false
				plans[i].LastState = "paused-error"
				plans[i].LastError = "后台状态不能持久化，安全暂停；核对存储与检查点后重新启用"
			}
		}
		return map[string]any{"plans": plans, "plan_errors": failures}, nil
	}
	if !syncPlanID.MatchString(in.ResourceID) {
		return nil, errors.New("计划标识应为 3–64 位小写字母数字或短横线")
	}
	path := s.syncPlanPath(in.ResourceID)
	var plan moduleSyncPlan
	err := moduleRead(path, &plan)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("现有计划损坏，拒绝覆盖")
	}
	if exists {
		if err = validateSyncPlan(plan); err != nil {
			return nil, err
		}
		if plan.ID != in.ResourceID {
			return nil, errors.New("计划身份与文件名不匹配，拒绝执行或覆盖")
		}
	}
	if action == "run-plan" {
		if !exists {
			return nil, errors.New("同步计划不存在")
		}
		return s.executeSyncPlan(ctx, &plan, "manual", time.Now().UTC())
	}
	if exists && in.ExpectedRevision != plan.Revision || !exists && in.ExpectedRevision != 0 {
		return nil, errors.New("计划配置已改变，请重新选择计划")
	}
	now := time.Now().UTC()
	switch action {
	case "schedule":
		if in.TargetProjectID != "" {
			return nil, errors.New("自动计划当前仅支持本机受管网站；隔离项目使用手动同步")
		}
		candidate := moduleSyncPlan{ID: in.ResourceID, SiteID: in.SiteID, TargetSiteID: in.TargetSiteID, Excludes: in.Excludes, Interval: in.Interval, Enabled: in.Enabled, Revision: plan.Revision + 1, LastState: "pending"}
		if !candidate.Enabled {
			candidate.LastState = "paused"
		}
		if candidate.Enabled {
			candidate.NextRunAt = now.Add(time.Duration(candidate.Interval) * time.Second).Format(time.RFC3339)
		}
		if err = validateSyncPlan(candidate); err != nil {
			return nil, err
		}
		paths, _ := filepath.Glob(filepath.Join(s.moduleDir("files-sync"), "plans", "*.json"))
		if !exists && len(paths) >= 32 {
			return nil, errors.New("最多 32 个同步计划")
		}
		// Resolve both exact managed roots before persisting any policy.
		for _, site := range []string{candidate.SiteID, candidate.TargetSiteID} {
			f, err := s.openFiles(site)
			if err != nil {
				return nil, err
			}
			f.Close()
		}
		plan = candidate
	case "pause-plan", "resume-plan":
		if !exists {
			return nil, errors.New("同步计划不存在")
		}
		plan.Enabled = action == "resume-plan"
		plan.Revision++
		plan.LastState = "paused"
		plan.NextRunAt = ""
		if plan.Enabled {
			plan.LastState = "pending"
			plan.FailureCount = 0
			plan.LastError = ""
			plan.NextRunAt = now.Add(time.Duration(plan.Interval) * time.Second).Format(time.RFC3339)
		}
	case "remove-plan":
		if !exists {
			return nil, errors.New("同步计划不存在")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
		return map[string]any{"removed": in.ResourceID, "scope": "仅移除计划；网站文件和增量检查点保留"}, nil
	default:
		return nil, errors.New("同步计划动作无效")
	}
	if err = moduleWrite(path, plan); err != nil {
		return nil, err
	}
	delete(s.moduleAutoBlocked, "files-sync/"+plan.ID)
	return map[string]any{"plan": plan}, nil
}
func (s *Service) executeSyncPlan(ctx context.Context, plan *moduleSyncPlan, trigger string, now time.Time) (any, error) {
	if plan.LastState == "running" {
		return nil, errors.New("同步计划仍在执行，不能重叠运行")
	}
	plan.LastState = "running"
	plan.LastStartedAt = now.Format(time.RFC3339)
	plan.LastError = ""
	if err := moduleWrite(s.syncPlanPath(plan.ID), plan); err != nil {
		s.blockModuleAutomation("files-sync/" + plan.ID)
		return nil, err
	}
	input := core.AppModuleInput{SiteID: plan.SiteID, TargetSiteID: plan.TargetSiteID, Excludes: plan.Excludes, ResourceID: plan.ID}
	result, runErr := s.moduleSync(ctx, input, false)
	plan.LastFinishedAt = time.Now().UTC().Format(time.RFC3339)
	plan.LastState = "succeeded"
	plan.Copied = 0
	plan.Conflicts = 0
	if r, ok := result.(map[string]any); ok {
		plan.Copied = moduleCount(r, "copied")
		plan.Conflicts = moduleCount(r, "conflicts")
		if plan.Conflicts > 0 {
			plan.LastState = "conflicts"
		}
	}
	delay := plan.Interval
	if runErr != nil {
		plan.LastState = "failed"
		plan.FailureCount++
		plan.LastError = runErr.Error()
		if len(plan.LastError) > 512 {
			plan.LastError = plan.LastError[:512] + "…"
		}
		for i := 0; i < plan.FailureCount && i < 4; i++ {
			delay = min(delay*2, 86400)
		}
		if plan.FailureCount >= 3 {
			plan.Enabled = false
			plan.LastState = "paused-error"
		}
	}
	if runErr == nil {
		plan.FailureCount = 0
	}
	plan.NextRunAt = ""
	if plan.Enabled {
		plan.NextRunAt = time.Now().UTC().Add(time.Duration(delay) * time.Second).Format(time.RFC3339)
	}
	historyErr := s.appendModuleEvent("files-sync", "run-plan", trigger, input, result, runErr)
	if historyErr != nil {
		plan.LastError = "业务可能已执行，但执行历史保存失败：" + historyErr.Error()
		plan.LastState = "paused-error"
		plan.Enabled = false
		plan.NextRunAt = ""
	}
	if err := moduleWrite(s.syncPlanPath(plan.ID), plan); err != nil {
		s.blockModuleAutomation("files-sync/" + plan.ID)
		return nil, fmt.Errorf("计划执行状态保存失败，请核对文件与检查点：%w", err)
	}
	if historyErr != nil {
		return nil, historyErr
	}
	if runErr != nil {
		return nil, runErr
	}
	return map[string]any{"plan": plan, "result": result}, nil
}
func (s *Service) recoverSyncPlans() {
	plans, _ := s.readSyncPlans()
	for _, plan := range plans {
		if plan.LastState != "running" {
			continue
		}
		plan.Enabled = false
		plan.LastState = "interrupted"
		plan.NextRunAt = ""
		plan.LastError = "执行器重启时任务未完成；为保护目标文件已暂停，请核对检查点后恢复"
		plan.LastFinishedAt = core.Now()
		if err := moduleWrite(s.syncPlanPath(plan.ID), plan); err != nil {
			s.blockModuleAutomation("files-sync/" + plan.ID)
		}
		if err := s.appendModuleEvent("files-sync", "run-plan", "recovery", core.AppModuleInput{SiteID: plan.SiteID, ResourceID: plan.ID}, nil, errors.New(plan.LastError)); err != nil {
			s.blockModuleAutomation("files-sync/" + plan.ID)
		}
	}
}
func (s *Service) runDueSyncPlans(now time.Time) {
	if !s.moduleInstalled("files-sync") {
		return
	}
	plans, _ := s.readSyncPlans()
	for _, plan := range plans {
		next, err := time.Parse(time.RFC3339, plan.NextRunAt)
		if err != nil || !plan.Enabled || next.After(now) {
			continue
		}
		// Release the service lock between plans so other operations are not starved.
		s.mu.Lock()
		var fresh moduleSyncPlan
		if !s.moduleAutoBlocked["files-sync/"+plan.ID] && moduleRead(s.syncPlanPath(plan.ID), &fresh) == nil && validateSyncPlan(fresh) == nil && fresh.Enabled && fresh.Revision == plan.Revision && fresh.NextRunAt == plan.NextRunAt {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			result, err := s.executeSyncPlan(ctx, &fresh, "scheduled", now)
			cancel()
			report := map[string]any{"time": core.Now(), "action": "scheduled-sync", "result": result}
			if err != nil {
				report["error"] = err.Error()
			}
			_ = moduleWrite(filepath.Join(s.moduleDir("files-sync"), "last-report.json"), report)
		}
		s.mu.Unlock()
	}
}
