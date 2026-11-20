//go:build linux

package executor

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

// The existing three-file journal remains the only configuration authority.
// The owner is a PID/start-time plus the kernel-observed exclusive Apache lock;
// it grants only a bounded candidate start while that exact executor is alive.
type apacheRuntimeTransition struct {
	JobID      string            `json:"job_id"`
	PreviousID string            `json:"previous_id"`
	NextID     string            `json:"next_id"`
	ApplyOwner *moduleApplyOwner `json:"apply_owner"`
	BootID     string            `json:"boot_id"`
}

func (s *Service) validateApacheRuntimeTransaction(tx wafTransaction) error {
	a := tx.ApacheRuntime
	if a == nil {
		return nil
	}
	if s.fileTransactionApplication != "apache-waf" || tx.Format != 2 || !core.ValidID(a.JobID) || a.ApplyOwner == nil || a.ApplyOwner.PID <= 1 || a.ApplyOwner.StartTime == 0 || !apacheRuntimeBootIdentity.MatchString(a.BootID) || a.PreviousID != runtimecatalog.ApacheLegacyID || a.NextID != runtimecatalog.ApacheCurrentID || len(tx.Changes) != 3 {
		return errors.New("Apache 运行版本事务身份、来源或执行所有者无效")
	}
	for i, path := range s.apacheWAFConfigurationPaths() {
		if tx.Changes[i].Path != path {
			return errors.New("Apache 运行版本事务文件顺序无效")
		}
	}
	change := tx.Changes[0]
	old, oldErr := apacheSourceRelease(string(change.OldData))
	next, nextErr := apacheSourceRelease(string(change.NextData))
	if !change.OldExists || !change.NextExists || oldErr != nil || nextErr != nil || old.ID != a.PreviousID || next.ID != a.NextID {
		return errors.New("Apache 运行版本事务必须保留原配置并绑定完整的新版本配置")
	}
	return nil
}

func (s *Service) authorizeApacheRuntimeCandidate(ctx context.Context, tx wafTransaction) error {
	if tx.ApacheRuntime == nil {
		return errors.New("不是 Apache 运行版本候选事务")
	}
	if err := s.wafTransactionContract(tx); err != nil {
		return err
	}
	if err := s.authorizeModuleCandidate(ctx, filepath.Join(s.moduleDir("apache-waf"), "waf-configuration.lock"), tx.ApacheRuntime.ApplyOwner); err != nil {
		return err
	}
	boot, err := s.apacheRuntimeBootID()
	if err != nil || boot != tx.ApacheRuntime.BootID {
		return errors.New("Apache 原切换执行器属于不同启动，必须先恢复原配置")
	}
	useNext := tx.State != "recovered"
	for _, change := range tx.Changes {
		same, err := s.wafCurrentMatches(change, useNext)
		if err != nil || !same {
			return errors.New("Apache 候选启动的完整配置、UID/GID 或摘要不一致，未启动")
		}
	}
	id := tx.ApacheRuntime.NextID
	if !useNext {
		id = tx.ApacheRuntime.PreviousID
	}
	_, err = LoadRuntime(id)
	return err
}

var apacheRuntimeBootIdentity = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func (s *Service) apacheRuntimeBootID() (string, error) {
	raw, err := readModuleProcFile(s.systemPath("/proc/sys/kernel/random/boot_id"), 128)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !apacheRuntimeBootIdentity.MatchString(id) {
		return "", errors.New("Apache 执行器启动身份不可核实")
	}
	return id, nil
}
