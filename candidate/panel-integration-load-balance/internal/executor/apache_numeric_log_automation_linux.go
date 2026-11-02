//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"time"
)

// The coordinator belongs to panel-core maintenance. The original application's
// signed identity and three-file WAF transaction remain unchanged. Its private
// policy is opt-in; a status read or programme upgrade never creates it.
type apacheNumericAutomationRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Enabled          bool  `json:"enabled"`
	RotateMiB        int   `json:"rotate_mib"`
	MaxAgeMinutes    int   `json:"max_age_minutes"`
}

// Apache is installed as a module. The separate software-manifest reader is a
// closed authority for other applications and must not be widened or used here.
func (s *Service) apacheNumericInstalledConfig() (core.WAFConfig, bool, error) {
	record, err := s.moduleInstalledRecord("apache-waf")
	if errors.Is(err, os.ErrNotExist) {
		return core.WAFConfig{}, false, nil
	}
	if err != nil {
		return core.WAFConfig{}, false, err
	}
	version, ok := record["version"].(string)
	if !ok || version == "" {
		return core.WAFConfig{}, false, errors.New("Apache 安装版本缺失或无效，未作为未安装或采用默认值")
	}
	if version != core.ApacheWAFNativeBodyVersion {
		return core.WAFConfig{}, false, nil
	}
	settings, ok := record["settings"].(map[string]any)
	if !ok {
		return core.WAFConfig{}, false, errors.New("Apache 原安装策略缺失，未采用默认值")
	}
	cfg, err := core.DecodeApacheWAFNativeBodyConfig(settings)
	return cfg, true, err
}

func verifyApacheNumericRotationEngine(ctx context.Context, cfg core.WAFConfig) error {
	if cfg.Body == nil || !core.ValidID(cfg.Body.EngineJobID) {
		return errors.New("须先明确选择已验证的本机请求体引擎；不会自动构建或启用防护")
	}
	// Numerical logs can outlive active sites. Rehash the selected sealed engine
	// even when every site is paused, rather than relying on active-only health.
	return verifyApacheBodyBuildContext(ctx, cfg.Body.EngineJobID)
}

func (s *Service) apacheNumericRotationFence(ctx context.Context, intent string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record, _, err := s.readApacheNumericRotationRecord()
	if errors.Is(err, os.ErrNotExist) && intent == "" {
		return nil
	}
	if err != nil {
		return err
	}
	if intent != "" {
		if !core.ValidID(intent) || record.ID != intent || record.State != "rotating" || !record.Policy.Enabled {
			return errors.New("Apache 自动轮转持久意图不符，未截断")
		}
	} else if record.State == "rotating" || record.State == "unknown" {
		return errors.New("Apache 自动轮转结果未知；请按原摘要核对，未重复截断或跨过原操作")
	}
	return nil
}

func (s *Service) apacheNumericAutomationStatus(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := map[string]any{
		"configured": false, "policy_revision": int64(0), "policy": core.DefaultWAFBodyLogRotation(),
		"record": nil, "record_sha256": "", "read_only": true, "core_maintenance": true,
		"check_interval_seconds": 60, "automatic_deletion": false,
	}
	record, digest, err := s.readApacheNumericRotationRecord()
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	out["configured"], out["policy_revision"], out["policy"] = true, record.ConfigRevision, record.Policy
	out["record"], out["record_sha256"] = record, digest
	return out, nil
}

func (s *Service) configureApacheNumericAutomation(ctx context.Context, request apacheNumericAutomationRequest, now time.Time) (map[string]any, error) {
	policy := core.WAFBodyLogRotationConfig{Enabled: request.Enabled, RotateMiB: request.RotateMiB, MaxAgeMinutes: request.MaxAgeMinutes}
	if request.ExpectedRevision < 0 || request.ExpectedRevision > 1000000000 || core.ValidateWAFBodyLogRotation(&policy) != nil {
		return nil, errors.New("Apache 自动轮转配置或预期修订无效")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = s.verifyApacheNumericLock(lock); err != nil {
		return nil, err
	}
	record, _, err := s.readApacheNumericRotationRecord()
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, err
	}
	if record.ConfigRevision != request.ExpectedRevision {
		return nil, errors.New("Apache 自动轮转配置修订已变化，请先读取原配置再保存")
	}
	if missing && policy == core.DefaultWAFBodyLogRotation() || !missing && record.Policy == policy {
		return s.apacheNumericAutomationStatus(ctx)
	}
	if record.ConfigRevision >= 1000000000 {
		return nil, errors.New("配置修订达到固定上限，保留原证据")
	}
	if policy.Enabled {
		if err = s.apacheNumericLogHealthLocked(ctx); err != nil {
			return nil, err
		}
		cfg, native, readErr := s.apacheNumericInstalledConfig()
		if readErr != nil {
			return nil, readErr
		}
		if !native {
			return nil, errors.New("Apache 原签名请求体安装无法核实")
		}
		if err = verifyApacheNumericRotationEngine(ctx, cfg); err != nil {
			return nil, err
		}
		if err = s.verifyApacheWAFHealth(ctx, core.ApacheWAFNativeBodyVersion, core.WAFSettings(cfg)); err != nil {
			return nil, err
		}
		record.Revision = cfg.Policy.Revision
	}
	if missing {
		record.Format, record.ID, record.State = 1, core.ID(), "idle"
		record.WindowStartedAt, record.CheckedAt = now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)
		record.History = []apacheNumericRotationOutcome{}
	}
	// Disabling is allowed while an outcome is unknown, but does not clear its
	// fence, historical identity, time window or evidence. Saving thresholds does
	// not restart a previously accumulated rotation window.
	record.ConfigRevision++
	record.Policy = policy
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.writeApacheNumericRotationRecord(record); err != nil {
		return nil, err
	}
	return s.apacheNumericAutomationStatus(ctx)
}
