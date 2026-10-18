//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"local/panel/internal/core"
)

func validateStatisticsNextInstalled(raw []byte) (map[string]any, error) {
	var next map[string]any
	allowed := map[string]bool{"id": true, "version": true, "settings": true, "installed_at": true, "updated_at": true, "installation_id": true}
	if len(raw) == 0 || len(raw) > 1<<20 || decodeApacheWAFPrivateJSON(raw, &next, allowed, 100000) != nil || next["id"] != "website-statistics-v2" || next["version"] != "2.5.0" && next["version"] != "2.6.0" {
		return nil, errors.New("统计日志格式候选安装记录不是闭合的固定应用身份")
	}
	epoch, present := next["installation_id"]
	if next["version"] == statisticsGeographyVersion {
		id, ok := epoch.(string)
		if !present || !ok || !core.ValidID(id) {
			return nil, errors.New("统计地域候选实例标识无效")
		}
	} else if present {
		return nil, errors.New("旧统计版本不能携带地域实例标识")
	}
	if settings, exists := next["settings"]; exists && settings != nil {
		if _, ok := settings.(map[string]any); !ok {
			return nil, errors.New("统计候选设置结构异常")
		}
		data, err := json.Marshal(settings)
		if err != nil || len(data) > 16384 {
			return nil, errors.New("统计候选设置超限")
		}
	}
	for _, name := range []string{"installed_at", "updated_at"} {
		if value, exists := next[name]; exists {
			text, ok := value.(string)
			if !ok {
				return nil, errors.New("统计候选时间结构异常")
			}
			if _, err := time.Parse(time.RFC3339, text); err != nil {
				return nil, errors.New("统计候选时间无法核对")
			}
		}
	}
	return next, nil
}

func (s *Service) statisticsLogTransactionService() *Service {
	return &Service{Config: s.Config, fileTransactionApplication: "statistics-nginx"}
}
func (s *Service) statisticsLogConfigurationPaths() []string {
	return []string{s.Config.NginxConf, filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json")}
}
func (s *Service) statisticsLogStableBackup(path string) (fileBackup, error) {
	b := fileBackup{path: path, mode: 0644}
	if !s.wafChangePathAllowed(path) {
		return b, errors.New("统计日志格式备份路径不属于两个固定文件")
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
	if err = ownedRuntimePath(path, false); err != nil {
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
	afterOwner, err := fileOwnerForInfo(after)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || *owner != *afterOwner || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return b, errors.New("统计日志配置备份期间发生外部修改")
	}
	b.data, b.existed, b.mode, b.owner = data, true, before.Mode().Perm(), owner
	return b, nil
}

// Caller owns the same shared configuration lock for the whole prepare/apply/
// recover sequence. The installed record is the LAST publication, after the
// exact candidate passes native syntax, reload and the private loaded-worker
// fingerprint. This primitive alone is not yet a signed2.5 lifecycle.
func (s *Service) applyStatisticsLogPlan(ctx context.Context, plan []wafConfigChange) error {
	if len(plan) != 2 {
		return errors.New("统计日志格式计划不完整")
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		bounded, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		recoverErr := s.recoverStatisticsLogBeforeMutation(bounded)
		return fmt.Errorf("统计日志格式未确认提交；恢复完成=%v，原证据保留：%w", recoverErr == nil, errors.Join(cause, recoverErr))
	}
	if err = ctx.Err(); err != nil {
		return rollback(err)
	}
	if match, e := s.wafCurrentMatches(plan[0], false); e != nil || !match {
		return rollback(errors.New("统计原日志配置在写入前改变"))
	}
	if err = wafApplyChange(plan[0], true); err != nil {
		return rollback(err)
	}
	if err = s.wafOwnedDirectory(filepath.Dir(s.statisticsHealthSocket()), true); err != nil {
		return rollback(err)
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return rollback(err)
	}
	if _, err = s.moduleCommand(ctx, 15*time.Second, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return rollback(err)
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return rollback(err)
	}
	if err = s.waitStatisticsHealth(ctx, plan[0].NextData); err != nil {
		return rollback(err)
	}
	if err = ctx.Err(); err != nil {
		return rollback(err)
	}
	if match, e := s.wafCurrentMatches(plan[1], false); e != nil || !match {
		return rollback(errors.New("统计安装记录在发布前改变"))
	}
	if err = wafApplyChange(plan[1], true); err != nil {
		return rollback(err)
	}
	for _, change := range plan {
		if match, e := s.wafCurrentMatches(change, true); e != nil || !match {
			return rollback(errors.New("统计日志格式或安装记录在最终核对时改变"))
		}
	}
	tx.State = "committed"
	if err = s.finishWAFTransaction(tx); err != nil {
		return fmt.Errorf("统计日志变更已发布但事务归档未完成，不能重复安装：%w", err)
	}
	return nil
}
func (s *Service) recoverStatisticsLogBeforeMutation(ctx context.Context) error {
	if _, err := s.readWAFTransaction(); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := s.recoverWAFTransaction(); err != nil {
		return err
	}
	tx, err := s.readWAFTransaction()
	if err != nil {
		return err
	}
	if err = s.wafOwnedDirectory(filepath.Dir(s.statisticsHealthSocket()), true); err != nil {
		return err
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	if _, err = s.moduleCommand(ctx, 15*time.Second, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return err
	}
	state, stateErr := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "nginx")
	active := strings.TrimSpace(state) == "active" && stateErr == nil
	if !active {
		// Startup's ExecStartPre has no master yet. Require MainPID=0 even
		// for inactive/failed states; never start a stopped service here.
		status := strings.TrimSpace(state)
		pid, pidErr := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "nginx", "--property=MainPID", "--value")
		if (status != "inactive" && status != "failed" && status != "activating") || pidErr != nil || strings.TrimSpace(pid) != "0" {
			return errors.New("Nginx 服务状态或主进程无法核对，保留统计日志恢复事务且不自动启动服务")
		}
	} else {
		if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
			return err
		}
		data := tx.Changes[0].OldData
		if tx.State == "committed" {
			data = tx.Changes[0].NextData
		}
		if err = s.waitStatisticsHealth(ctx, data); err != nil {
			return err
		}
	}
	for _, change := range tx.Changes {
		if match, e := s.wafCurrentMatches(change, tx.State == "committed"); e != nil || !match {
			return errors.New("恢复后统计日志文件不匹配，原证据保留")
		}
	}
	return s.finishWAFTransaction(tx)
}
func (s *Service) statisticsLogPlan(nextInstalled []byte) ([]wafConfigChange, error) {
	next, err := validateStatisticsNextInstalled(nextInstalled)
	if err != nil {
		return nil, err
	}
	paths := s.statisticsLogConfigurationPaths()
	before, err := s.statisticsLogStableBackup(paths[0])
	if err != nil || !before.existed {
		return nil, errors.New("原统计日志格式配置缺失或不能安全备份")
	}
	candidate, err := statisticsNginxHealthConfig(before.data, s.statisticsHealthSocket(), core.ID())
	if err != nil {
		return nil, err
	}
	installed, err := s.statisticsLogStableBackup(paths[1])
	if err != nil {
		return nil, err
	}
	if len(nextInstalled) == 0 || len(nextInstalled) > 1<<20 {
		return nil, errors.New("统计私有安装记录超限或缺失")
	}
	if installed.existed {
		previous, err := s.moduleInstalledRecord("website-statistics-v2")
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(previous["settings"], next["settings"]) || !reflect.DeepEqual(previous["installed_at"], next["installed_at"]) {
			return nil, errors.New("统计日志格式升级不能改写原配置或安装时间")
		}
		if previous["version"] == statisticsGeographyVersion && previous["installation_id"] != next["installation_id"] {
			return nil, errors.New("统计更新不能改写已有地域实例标识")
		}
	}
	plan := []wafConfigChange{
		{Path: paths[0], OldData: before.data, OldExists: true, OldMode: before.mode, OldOwner: before.owner, NextData: candidate, NextExists: true, NextMode: before.mode, NextOwner: before.owner},
		{Path: paths[1], OldData: installed.data, OldExists: installed.existed, OldMode: installed.mode, OldOwner: installed.owner, NextData: bytes.Clone(nextInstalled), NextExists: true, NextMode: 0600, NextOwner: installed.owner},
	}
	return plan, nil
}

// Readers hold the same cross-process SH lock until both history data and
// cursors have been committed. No pending (including unreadable) journal is
// interpreted as a successfully installed/migrated application.
func (s *Service) statisticsLogReadLock() (*os.File, error) {
	f, err := s.statisticsLogTransactionService().lockWAFObservation()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.statisticsLogTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		f.Close()
		return nil, errors.New("统计日志格式有待恢复事务；暂缓采集，原数据及进度保留")
	}
	return f, nil
}

// Only retry the typed pre-acquisition contention result. This does not retry
// ingestion, configuration changes or unknown outcomes. The original worker
// deadline bounds waiting AND the eventual reads/commit; pending transactions,
// unsafe paths and all other failures remain immediate, visible refusals.
func (s *Service) statisticsLogReadLockContext(ctx context.Context) (*os.File, error) {
	if ctx == nil {
		return nil, errors.New("统计采集锁缺少有效的时间预算")
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lock, err := s.statisticsLogReadLock()
		if err == nil {
			if err := ctx.Err(); err != nil {
				lock.Close()
				return nil, err
			}
			return lock, nil
		}
		if !errors.Is(err, errWAFConfigurationBusy) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func RecoverStatisticsLogConfiguration() error {
	s := nativeWAFService().statisticsLogTransactionService()
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
	return s.recoverStatisticsLogBeforeMutation(ctx)
}
