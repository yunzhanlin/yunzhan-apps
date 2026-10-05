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
	Enabled      bool   `json:"enabled"`
	Interval     int    `json:"interval"`
	NextRunAt    string `json:"next_run_at,omitempty"`
	LastState    string `json:"last_state"`
	LastError    string `json:"last_error,omitempty"`
	FailureCount int    `json:"failure_count"`
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
	if policy.SiteID != site || !core.ValidID(site) || policy.Interval < 60 || policy.Interval > 86400 {
		return policy, errors.New("监控策略损坏，拒绝自动执行")
	}
	if policy.NextRunAt != "" {
		if _, err := time.Parse(time.RFC3339, policy.NextRunAt); err != nil {
			return policy, errors.New("监控时间无效")
		}
	}
	return policy, nil
}
func (s *Service) resetIntegrityControl(id, site string, interval int) error {
	if interval == 0 {
		interval = 60
	}
	if interval < 60 || interval > 86400 {
		return errors.New("监控间隔应为 60–86400 秒")
	}
	return moduleWrite(s.integrityControlPath(id, site), moduleIntegrityPolicy{SiteID: site, Enabled: true, Interval: interval, LastState: "pending", NextRunAt: time.Now().UTC().Add(time.Duration(interval) * time.Second).Format(time.RFC3339)})
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
			row := map[string]any{"site_id": site, "enabled": policy.Enabled, "interval": policy.Interval, "next_run_at": policy.NextRunAt, "last_state": policy.LastState, "last_error": policy.LastError, "signature_verified": err == nil, "excludes": baseline.Excludes, "auto_restore": baseline.AutoRestore, "files": len(baseline.Files), "created_at": baseline.CreatedAt}
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
		return map[string]any{"policies": rows, "scope": "暂停不删除基线和备份；签名错误及连续 3 次失败会停止后台恢复"}, nil
	}
	if !core.ValidID(in.SiteID) {
		return nil, errors.New("请选择网站的监控策略")
	}
	if action != "pause" && action != "resume" {
		return nil, errors.New("监控管理动作无效")
	}
	if action == "resume" {
		if _, err := s.readIntegrityBaseline(id, in.SiteID); err != nil {
			return nil, err
		}
	}
	policy, err := s.readIntegrityPolicy(id, in.SiteID)
	if err != nil {
		return nil, err
	}
	// Pause remains possible for archived websites or broken signatures.
	if _, err := os.Lstat(filepath.Join(s.moduleDir(id), "baselines", in.SiteID, "baseline.json")); err != nil {
		return nil, errors.New("基线不存在")
	}
	policy.Enabled = action == "resume"
	policy.LastState = "paused"
	policy.NextRunAt = ""
	if policy.Enabled {
		policy.LastState = "pending"
		policy.LastError = ""
		policy.FailureCount = 0
		policy.NextRunAt = time.Now().UTC().Add(time.Duration(policy.Interval) * time.Second).Format(time.RFC3339)
	}
	if err = moduleWrite(s.integrityControlPath(id, in.SiteID), policy); err != nil {
		return nil, err
	}
	delete(s.moduleAutoBlocked, id+"/"+in.SiteID)
	return map[string]any{"site_id": in.SiteID, "enabled": policy.Enabled, "interval": policy.Interval, "next_run_at": policy.NextRunAt}, nil
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
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			input := core.AppModuleInput{SiteID: site}
			result, err := s.moduleIntegrity(ctx, id, "check", input)
			cancel()
			historyErr := s.appendModuleEvent(id, "check", "scheduled", input, result, err)
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
			policy.NextRunAt = ""
			if policy.Enabled {
				policy.NextRunAt = time.Now().UTC().Add(time.Duration(delay) * time.Second).Format(time.RFC3339)
			}
			report := map[string]any{"time": core.Now(), "action": "scheduled-check", "result": result}
			if err != nil {
				report["error"] = err.Error()
			}
			_ = moduleWrite(filepath.Join(s.moduleDir(id), "last-report.json"), report)
			if stateErr := moduleWrite(s.integrityControlPath(id, site), policy); stateErr != nil {
				s.blockModuleAutomation(id + "/" + site)
				_ = s.appendModuleEvent(id, "policy-save", "scheduled", input, nil, stateErr)
			}
			s.mu.Unlock()
		}
	}
}
