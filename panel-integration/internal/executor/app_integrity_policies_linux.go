//go:build linux

package executor

import (
	"context"
	"crypto/hmac"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type moduleIntegrityPolicy struct {
	SiteID       string `json:"site_id"`
	Revision     int64  `json:"revision"`
	Enabled      bool   `json:"enabled"`
	Realtime     bool   `json:"realtime"`
	Interval     int    `json:"interval"`
	NextRunAt    string `json:"next_run_at,omitempty"`
	LastState    string `json:"last_state"`
	LastError    string `json:"last_error,omitempty"`
	FailureCount int    `json:"failure_count"`
	LastTrigger  string `json:"last_trigger,omitempty"`
	LastCheckAt  string `json:"last_check_at,omitempty"`
}

func (s *Service) blockModuleAutomation(key string) {
	if s.moduleAutoBlocked == nil {
		s.moduleAutoBlocked = map[string]bool{}
	}
	s.moduleAutoBlocked[key] = true
}
func (s *Service) integrityControlPath(id, site string) string {
	return filepath.Join(s.moduleDir(id), "baselines", site, "monitoring.json")
}
func (s *Service) readIntegrityPolicy(id, site string) (moduleIntegrityPolicy, error) {
	policy := moduleIntegrityPolicy{SiteID: site, Enabled: true, Interval: 60, LastState: "pending"}
	err := moduleRead(s.integrityControlPath(id, site), &policy)
	if errors.Is(err, os.ErrNotExist) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	if policy.SiteID != site || !core.ValidID(site) || policy.Interval < 60 || policy.Interval > 86400 || policy.Revision < 0 || policy.Revision == int64(^uint64(0)>>1) {
		return policy, errors.New("监控策略损坏，拒绝自动执行")
	}
	if policy.NextRunAt != "" {
		if _, err := time.Parse(time.RFC3339, policy.NextRunAt); err != nil {
			return policy, errors.New("监控时间无效")
		}
	}
	return policy, nil
}
func (s *Service) resetIntegrityControl(id, site string, interval int, realtime bool) error {
	if interval == 0 {
		interval = 60
	}
	if interval < 60 || interval > 86400 {
		return errors.New("监控间隔应为 60–86400 秒")
	}
	old, err := s.readIntegrityPolicy(id, site)
	if err != nil {
		return err
	}
	return moduleWrite(s.integrityControlPath(id, site), moduleIntegrityPolicy{SiteID: site, Revision: old.Revision + 1, Enabled: true, Realtime: realtime, Interval: interval, LastState: "pending", NextRunAt: time.Now().UTC().Add(time.Duration(interval) * time.Second).Format(time.RFC3339)})
}
func (s *Service) readIntegrityBaseline(id, site string) (moduleBaseline, error) {
	var baseline moduleBaseline
	err := moduleRead(filepath.Join(s.moduleDir(id), "baselines", site, "baseline.json"), &baseline)
	if err != nil {
		return baseline, err
	}
	key, err := s.existingBaselineKey()
	if err != nil {
		return baseline, err
	}
	if len(key) != 32 || baseline.SiteID != site || !hmac.Equal([]byte(baseline.Signature), []byte(baselineSignature(baseline, key))) {
		return baseline, errors.New("基线签名校验失败，不能启用自动保护")
	}
	return baseline, nil
}
func (s *Service) moduleIntegrityControl(id, action string, in core.AppModuleInput) (any, error) {
	if action == "policies" {
		paths, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "baselines", "*", "baseline.json"))
		sort.Strings(paths)
		rows := []map[string]any{}
		if len(paths) > 100 {
			paths = paths[:100]
		}
		for _, path := range paths {
			site := filepath.Base(filepath.Dir(path))
			if !core.ValidID(site) {
				continue
			}
			baseline, err := s.readIntegrityBaseline(id, site)
			policy, controlErr := s.readIntegrityPolicy(id, site)
			row := map[string]any{"site_id": site, "revision": policy.Revision, "enabled": policy.Enabled, "realtime": policy.Realtime, "interval": policy.Interval, "next_run_at": policy.NextRunAt, "last_state": policy.LastState, "last_error": policy.LastError, "last_trigger": policy.LastTrigger, "last_check_at": policy.LastCheckAt, "signature_verified": err == nil, "excludes": baseline.Excludes, "auto_restore": baseline.AutoRestore, "files": len(baseline.Files), "created_at": baseline.CreatedAt}
			status := s.moduleWatchStatus[id+"/"+site]
			if !policy.Enabled || !policy.Realtime {
				status.State = "disabled"
			} else if status.State == "" {
				status.State = "pending"
			}
			if err != nil || controlErr != nil || s.moduleAutoBlocked[id+"/"+site] {
				status.State = "degraded"
			}
			row["watcher_state"] = status.State
			row["watch_directories"] = status.Directories
			row["watch_overflows"] = status.Overflows
			row["watch_error"] = status.Error
			if err != nil {
				row["last_error"] = err.Error()
				row["enabled"] = false
			}
			if controlErr != nil {
				row["last_error"] = controlErr.Error()
				row["enabled"] = false
			}
			if s.moduleAutoBlocked[id+"/"+site] {
				row["enabled"] = false
				row["last_error"] = "后台状态不能持久化，安全暂停；核对存储后重新启用"
			}
			rows = append(rows, row)
		}
		return map[string]any{"policies": rows, "scope": "实时事件触发检查，定时扫描补查；暂停不删除备份。最多 4096 个实际目录监听，超限及溢出显示降级。不是内核写入拦截。"}, nil
	}
	if !core.ValidID(in.SiteID) {
		return nil, errors.New("请选择网站的监控策略")
	}
	if action != "pause" && action != "resume" && action != "watch-mode" {
		return nil, errors.New("监控管理动作无效")
	}
	if action == "resume" || action == "watch-mode" {
		if _, err := s.readIntegrityBaseline(id, in.SiteID); err != nil {
			return nil, err
		}
	}
	policy, err := s.readIntegrityPolicy(id, in.SiteID)
	if err != nil {
		return nil, err
	}
	if in.ExpectedRevision != 0 && in.ExpectedRevision != policy.Revision || action == "watch-mode" && in.ExpectedRevision != policy.Revision {
		return nil, errors.New("监控策略已变化，请重新选择最新策略")
	}
	// Pause remains possible for archived websites or broken signatures.
	if _, err := os.Lstat(filepath.Join(s.moduleDir(id), "baselines", in.SiteID, "baseline.json")); err != nil {
		return nil, errors.New("基线不存在")
	}
	if action == "watch-mode" {
		if in.Interval != 0 && (in.Interval < 60 || in.Interval > 86400) {
			return nil, errors.New("补查间隔应为 60–86400 秒")
		}
		if in.Interval != 0 {
			policy.Interval = in.Interval
		}
		policy.Realtime = in.Realtime
		// Changing detection mode must not resume a paused or failed policy.
		if policy.Enabled {
			policy.NextRunAt = time.Now().UTC().Add(time.Duration(policy.Interval) * time.Second).Format(time.RFC3339)
		}
	} else {
		policy.Enabled = action == "resume"
		policy.LastState = "paused"
		policy.NextRunAt = ""
		if policy.Enabled {
			policy.LastState = "pending"
			policy.LastError = ""
			policy.FailureCount = 0
			policy.NextRunAt = time.Now().UTC().Add(time.Duration(policy.Interval) * time.Second).Format(time.RFC3339)
		}
	}
	policy.Revision++
	if err = moduleWrite(s.integrityControlPath(id, in.SiteID), policy); err != nil {
		return nil, err
	}
	if action == "resume" {
		delete(s.moduleAutoBlocked, id+"/"+in.SiteID)
	}
	s.wakeIntegrityWatcher()
	return map[string]any{"site_id": in.SiteID, "revision": policy.Revision, "enabled": policy.Enabled, "realtime": policy.Realtime, "interval": policy.Interval, "next_run_at": policy.NextRunAt}, nil
}
func (s *Service) runDueIntegrity(now time.Time) {
	for _, id := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof"} {
		if !s.moduleInstalled(id) {
			continue
		}
		paths, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "baselines", "*", "baseline.json"))
		sort.Strings(paths)
		if len(paths) > 100 {
			paths = paths[:100]
		}
		for _, path := range paths {
			site := filepath.Base(filepath.Dir(path))
			if !core.ValidID(site) {
				continue
			}
			s.mu.Lock()
			policy, err := s.readIntegrityPolicy(id, site)
			next, _ := time.Parse(time.RFC3339, policy.NextRunAt)
			if err != nil || !policy.Enabled || next.After(now) || s.moduleAutoBlocked[id+"/"+site] {
				s.mu.Unlock()
				continue
			}
			s.runIntegrityPolicy(id, site, policy, "scheduled")
			s.mu.Unlock()
		}
	}
}

// The caller holds mu. A queued kernel event re-reads the policy under this same
// lock, so pause/revision changes cannot be followed by an old queued restore.
func (s *Service) runIntegrityPolicy(id, site string, policy moduleIntegrityPolicy, trigger string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	input := core.AppModuleInput{SiteID: site}
	result, err := s.moduleIntegrity(ctx, id, "check", input)
	cancel()
	changes := 0
	if value, ok := result.(map[string]any); ok {
		if sites, ok := value["sites"].([]any); ok {
			for _, item := range sites {
				if row, ok := item.(map[string]any); ok {
					changes += moduleCount(row, "changes")
				}
			}
		}
	}
	// Our own atomic restoration also raises inotify events. A successful check
	// with no differences must not create a noisy self-triggered history loop.
	var historyErr error
	if trigger == "scheduled" || trigger == "inotify-overflow" || changes != 0 || err != nil {
		historyErr = s.appendModuleEvent(id, "check", trigger, input, result, err)
	}
	policy.LastTrigger = trigger
	policy.LastCheckAt = core.Now()
	policy.LastState = "succeeded"
	policy.LastError = ""
	delay := policy.Interval
	if err == nil {
		policy.FailureCount = 0
	} else {
		policy.LastState = "failed"
		policy.FailureCount++
		policy.LastError = err.Error()
		for i := 0; i < policy.FailureCount && i < 4; i++ {
			delay = min(delay*2, 86400)
		}
		if policy.FailureCount >= 3 {
			policy.Enabled = false
			policy.LastState = "paused-error"
		}
	}
	if historyErr != nil {
		policy.Enabled = false
		policy.LastState = "paused-error"
		policy.LastError = "执行历史保存失败：" + historyErr.Error()
	}
	if len(policy.LastError) > 512 {
		policy.LastError = policy.LastError[:512] + "…"
	}
	oldNext := policy.NextRunAt
	policy.NextRunAt = ""
	if policy.Enabled {
		policy.NextRunAt = time.Now().UTC().Add(time.Duration(delay) * time.Second).Format(time.RFC3339)
		if trigger != "scheduled" && err == nil && historyErr == nil {
			// Healthy event checks must not postpone periodic full checks.
			policy.NextRunAt = oldNext
		}
	}
	report := map[string]any{"time": core.Now(), "action": trigger + "-check", "result": result}
	if err != nil {
		report["error"] = err.Error()
	}
	if trigger == "scheduled" || trigger == "inotify-overflow" || changes != 0 || err != nil {
		if reportErr := moduleWrite(filepath.Join(s.moduleDir(id), "last-report.json"), report); reportErr != nil {
			policy.Enabled = false
			policy.LastState = "paused-error"
			policy.LastError = "检查报告不能持久化：" + reportErr.Error()
			policy.NextRunAt = ""
		}
	}
	if stateErr := moduleWrite(s.integrityControlPath(id, site), policy); stateErr != nil {
		s.blockModuleAutomation(id + "/" + site)
		_ = s.appendModuleEvent(id, "policy-save", trigger, input, nil, stateErr)
	}
}
