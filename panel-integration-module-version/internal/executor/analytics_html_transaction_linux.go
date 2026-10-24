//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) analyticsHTMLTransactionService() *Service {
	return &Service{Config: s.Config, fileTransactionApplication: "analytics-html"}
}

func (s *Service) analyticsHTMLConfigurationPaths() []string {
	return []string{s.Config.NginxConf, s.systemPath("/etc/panel/analytics-html/health.conf"), s.systemPath("/etc/panel/analytics-html/active.json")}
}

func (s *Service) analyticsHTMLStableBackup(path string) (fileBackup, error) {
	b := fileBackup{path: path, mode: 0644}
	if !s.wafChangePathAllowed(path) {
		return b, errors.New("HTML 恢复路径不在固定三个文件内")
	}
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return b, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	if err := ownedRuntimePath(path, false); err != nil {
		return b, err
	}
	owner, err := fileOwnerForInfo(before)
	if err != nil {
		return b, err
	}
	data, err := apacheWAFReadStableFile(path, 1<<20)
	if err != nil {
		return b, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return b, err
	}
	nextOwner, err := fileOwnerForInfo(after)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || *owner != *nextOwner || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return b, errors.New("HTML 配置在备份期间被外部修改")
	}
	b.data, b.existed, b.mode, b.owner = data, true, before.Mode().Perm(), owner
	return b, nil
}

func (s *Service) recoverAnalyticsHTMLBeforeMutation(ctx context.Context) error {
	_, err := s.readWAFTransaction()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := s.recoverWAFTransaction(); err != nil {
		return err
	}
	tx, err := s.readWAFTransaction()
	if err != nil {
		return err
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	if _, err := s.moduleCommand(ctx, 30*time.Second, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return err
	}
	state, stateErr := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "nginx")
	if strings.TrimSpace(state) == "inactive" || strings.TrimSpace(state) == "failed" {
		return s.finishWAFTransaction(tx)
	}
	if strings.TrimSpace(state) == "activating" {
		pid, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "nginx", "--property=MainPID", "--value")
		if err == nil && strings.TrimSpace(pid) == "0" {
			return s.finishWAFTransaction(tx)
		}
		return errors.New("Nginx 启动中的主进程不可核实，保留 HTML 恢复事务")
	}
	if stateErr != nil || strings.TrimSpace(state) != "active" {
		return errors.New("Nginx 恢复时服务状态不可核实，保留事务")
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return err
	}
	last := tx.Changes[2]
	data, exists := last.OldData, last.OldExists
	if tx.State == "committed" {
		data, exists = last.NextData, last.NextExists
	}
	if exists {
		var identity analyticsHTMLEngineIdentity
		if json.Unmarshal(data, &identity) != nil || identity.State != "active" {
			return errors.New("HTML 恢复后的原引擎身份不可核实")
		}
		if err := s.waitAnalyticsHTMLLoaded(ctx, identity); err != nil {
			return err
		}
	} else {
		// No previous engine: reloaded configuration must have no live health
		// listener. A leftover Unix-socket inode is not a running worker.
		for attempt := 0; attempt < 8; attempt++ {
			if err := s.probeAnalyticsHTMLLoaded(ctx, analyticsHTMLEngineIdentity{}); err != nil {
				// A wrong fingerprint alone is insufficient to prove absence.
				absent, err := s.analyticsHTMLListenerAbsent(ctx)
				if err != nil {
					return err
				}
				if absent {
					return s.finishWAFTransaction(tx)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("HTML 恢复后仍有旧健康检查监听，保留事务")
	}
	return s.finishWAFTransaction(tx)
}

func (s *Service) applyAnalyticsHTMLPlanned(ctx context.Context, plan []wafConfigChange, identity analyticsHTMLEngineIdentity) error {
	if len(plan) != 3 {
		return errors.New("HTML 引擎完整应用计划缺失")
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		bounded, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		restoreErr := s.recoverAnalyticsHTMLBeforeMutation(bounded)
		return fmt.Errorf("HTML 引擎未确认提交，安全恢复完成=%v，原事务保留：%w", restoreErr == nil, errors.Join(cause, restoreErr))
	}
	for _, change := range plan[:2] {
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		match, err := s.wafCurrentMatches(change, false)
		if err != nil || !match {
			return rollback(errors.New("HTML 配置在应用期间被外部修改"))
		}
		if err := wafApplyChange(change, true); err != nil {
			return rollback(err)
		}
	}
	if _, err := s.moduleCommand(ctx, 30*time.Second, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return rollback(err)
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return rollback(err)
	}
	if err := s.waitAnalyticsHTMLLoaded(ctx, identity); err != nil {
		return rollback(err)
	}
	match, err := s.wafCurrentMatches(plan[2], false)
	if err != nil || !match {
		return rollback(errors.New("HTML 引擎记录在应用期间被外部修改"))
	}
	if err := wafApplyChange(plan[2], true); err != nil {
		return rollback(err)
	}
	for _, change := range plan {
		match, err := s.wafCurrentMatches(change, true)
		if err != nil || !match {
			return rollback(errors.New("HTML 最终配置或启用记录不匹配"))
		}
	}
	tx.State = "committed"
	if err := s.finishWAFTransaction(tx); err != nil {
		return fmt.Errorf("HTML 引擎已加载并核对，但恢复事务归档未完成：%w", err)
	}
	return nil
}

func RecoverAnalyticsHTMLConfiguration() error {
	s := nativeWAFService().analyticsHTMLTransactionService()
	if _, err := os.Lstat(s.wafPendingPath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.recoverAnalyticsHTMLBeforeMutation(ctx)
}
