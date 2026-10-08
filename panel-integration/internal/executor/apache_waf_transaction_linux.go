//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Share the owner-aware bounded journal engine, never its Nginx namespace or
// allowlist. Construct a fresh adapter: copying Service would copy its mutexes.
func (s *Service) apacheWAFTransactionService() *Service {
	return &Service{Config: s.Config, fileTransactionApplication: "apache-waf"}
}
func (s *Service) apacheWAFConfigurationPaths() []string {
	dir := s.moduleDir("apache-waf")
	return []string{s.Config.ApacheSiteConfig, filepath.Join(dir, "rules.conf"), filepath.Join(dir, "installed.json")}
}

func (s *Service) apacheWAFStableBackup(path string) (fileBackup, error) {
	b := fileBackup{path: path, mode: 0644}
	if !s.wafChangePathAllowed(path) {
		return b, errors.New("Apache 恢复路径不在固定三个文件内")
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
	// Both ordinary config and manifest are bounded before and during reading.
	limit := int64(1 << 20)
	if path == s.Config.ApacheSiteConfig {
		limit = 2 << 20
	}
	if path == filepath.Join(s.moduleDir("apache-waf"), "installed.json") {
		limit = 512 << 10
	}
	data, err := apacheWAFReadStableFile(path, limit)
	if err != nil {
		return b, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return b, err
	}
	afterOwner, err := fileOwnerForInfo(after)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || *owner != *afterOwner || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return b, errors.New("Apache 配置在备份期间被外部修改")
	}
	b.data, b.existed, b.mode, b.owner = data, true, before.Mode().Perm(), owner
	return b, nil
}

// Include unchanged files too: a recovery must validate the entire triplet
// before restoring any of it. The manifest is deliberately committed last.
func (s *Service) planApacheWAFTransaction(backups []fileBackup, source, rules string, manifest any, uninstall bool) ([]wafConfigChange, error) {
	paths := s.apacheWAFConfigurationPaths()
	if len(backups) != 3 {
		return nil, errors.New("Apache 完整配置备份缺失")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	values := [][]byte{[]byte(source), []byte(rules), append(data, '\n')}
	plan := make([]wafConfigChange, 3)
	for i, b := range backups {
		if b.path != paths[i] {
			return nil, errors.New("Apache 恢复文件顺序异常")
		}
		exists := !uninstall || i == 0
		owner := b.owner
		if owner == nil && exists {
			owner = &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		}
		mode := os.FileMode(0644)
		if i == 2 {
			mode = 0600
		}
		next := values[i]
		if !exists {
			next = nil
			owner = nil
		}
		plan[i] = wafConfigChange{Path: b.path, OldData: b.data, OldExists: b.existed, OldMode: b.mode, OldOwner: b.owner, NextData: next, NextExists: exists, NextMode: mode, NextOwner: owner}
	}
	return plan, nil
}

func (s *Service) recoverApacheWAFBeforeMutation(ctx context.Context) error {
	// Inspect before recovery so the chosen reload cannot conceal a bad journal.
	tx, err := s.readWAFTransaction()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.recoverWAFTransaction()
	if err != nil {
		return err
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	if _, err = s.Config.Run(ctx, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
		return fmt.Errorf("Apache 恢复后原生校验失败: %w", err)
	}
	state, stateErr := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")
	acknowledge := func() error {
		verified, e := s.readWAFTransaction()
		if e != nil {
			return e
		}
		return s.finishWAFTransaction(verified)
	}
	if strings.TrimSpace(state) == "inactive" || strings.TrimSpace(state) == "failed" {
		return acknowledge()
	} // Boot: Apache starts only after this preflight.
	if strings.TrimSpace(state) == "activating" {
		// Apache's own ExecStartPre runs in 'activating', not 'inactive'. Only
		// a verified zero MainPID permits cold acknowledgment; never treat a
		// possibly live daemon as not running merely because of the state label.
		pid, pidErr := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "panel-apache", "--property=MainPID", "--value")
		if pidErr == nil && strings.TrimSpace(pid) == "0" {
			return acknowledge()
		}
		return errors.New("Apache 启动中且进程状态不明确，保留恢复事务")
	}
	if stateErr != nil || strings.TrimSpace(state) != "active" {
		return errors.New("Apache 恢复后服务状态不可核实，保留事务")
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "panel-apache"); err != nil {
		return err
	}
	// Recovery of an old installation uses its exact version oracle, never the
	// new application's healthy badge. An uninstalled original has no WAF probe.
	c := tx.Changes[2]
	data := c.OldData
	exists := c.OldExists
	if tx.State == "committed" {
		data, exists = c.NextData, c.NextExists
	}
	if !exists {
		_, bindings, e := s.apacheWAFSource()
		if e != nil || len(bindings) == 0 {
			return errors.New("Apache 还原后的运行站点不可核实，保留事务")
		}
		ids := make([]string, 0, len(bindings))
		for id := range bindings {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if e = apacheWAFProbeAbsent(ctx, bindings[ids[0]][0]); e != nil {
			return e
		}
		return acknowledge()
	}
	var old struct {
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err = json.Unmarshal(data, &old); err != nil {
		return err
	}
	cfg, err := core.DecodeApacheWAFConfig(old.Settings)
	if err != nil {
		return err
	}
	source, _, err := s.apacheWAFSource()
	if err != nil {
		return err
	}
	domain, err := apacheWAFConfigurationFilesMatchVersion(source, cfg, filepath.Join(release.Prefix(), "modules/mod_remoteip.so"), s.apacheWAFConfigurationPaths()[1], old.Version)
	if err != nil {
		return err
	}
	if err = apacheWAFWaitLoadedVersion(ctx, cfg, domain, old.Version); err != nil {
		return err
	}
	return acknowledge()
}

func (s *Service) applyApacheWAFPlanned(ctx context.Context, plan []wafConfigChange, verify func(context.Context) error, add func(string)) error {
	if len(plan) != 3 || verify == nil {
		return errors.New("Apache 完整应用计划或加载验证器缺失")
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		return err
	}
	add("完整 Apache 配置恢复事务已持久化：" + tx.ID)
	rollback := func(cause error) error {
		bounded, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		restoreErr := s.recoverApacheWAFBeforeMutation(bounded)
		return fmt.Errorf("Apache 防护未确认提交，安全恢复完成=%v，恢复证据保留：%w", restoreErr == nil, errors.Join(cause, restoreErr))
	}
	for _, change := range plan[:2] {
		if err = ctx.Err(); err != nil {
			return rollback(err)
		}
		match, e := s.wafCurrentMatches(change, false)
		if e != nil || !match {
			return rollback(errors.New("Apache 配置在应用期间被外部修改"))
		}
		if err = wafApplyChange(change, true); err != nil {
			return rollback(err)
		}
	}
	if _, err = s.Config.Run(ctx, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
		return rollback(err)
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "panel-apache"); err != nil {
		return rollback(err)
	}
	if err = verify(ctx); err != nil {
		return rollback(err)
	}
	match, e := s.wafCurrentMatches(plan[2], false)
	if e != nil || !match {
		return rollback(errors.New("Apache 版本记录在应用期间被外部修改"))
	}
	if err = wafApplyChange(plan[2], true); err != nil {
		return rollback(err)
	}
	for _, change := range plan {
		match, e := s.wafCurrentMatches(change, true)
		if e != nil || !match {
			return rollback(errors.New("Apache 最终配置或版本记录字节不匹配"))
		}
	}
	tx.State = "committed"
	if err = s.finishWAFTransaction(tx); err != nil {
		return fmt.Errorf("Apache 已加载并核对新版配置，但事务归档未完成，证据保留：%w", err)
	}
	return nil
}

func RecoverApacheWAFConfiguration() error {
	if os.Geteuid() != 0 {
		return errors.New("Apache 防护恢复只能由 root 执行")
	}
	s := nativeWAFService().apacheWAFTransactionService()
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.recoverApacheWAFBeforeMutation(ctx)
}

func (s *Service) lockApacheWAFSiteMutation() (func(), error) {
	txs := s.apacheWAFTransactionService()
	_, pendingErr := os.Lstat(txs.wafPendingPath())
	_, installedErr := os.Lstat(txs.apacheWAFConfigurationPaths()[2])
	if errors.Is(pendingErr, os.ErrNotExist) && errors.Is(installedErr, os.ErrNotExist) {
		return func() {}, nil
	}
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(txs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, errors.New("Apache 防护存在未完成恢复事务，先恢复再修改网站")
	}
	return func() { _ = lock.Close() }, nil
}
