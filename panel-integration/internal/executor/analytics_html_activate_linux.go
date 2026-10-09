//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func (s *Service) activateAnalyticsHTML(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.moduleInstalled("website-analytics") {
		return errors.New("请先安装网站分析应用")
	}
	var installed struct {
		ID       string         `json:"id"`
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	// Installed manifests can carry extra historical bookkeeping fields. The
	// immutable build and active records below still use closed strict schemas.
	if err := moduleRead(s.moduleDir("website-analytics")+"/installed.json", &installed); err != nil || installed.ID != "website-analytics" || installed.Version != "2.3.0" {
		return errors.New("请先通过签名应用更新安装网站分析 2.3.0")
	}
	txs := s.analyticsHTMLTransactionService()
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	for _, path := range []string{s.wafPendingPath(), s.loadBalancePendingPath()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("其他 Nginx 入口存在待恢复事务，未覆盖配置")
		}
	}
	if err := txs.recoverAnalyticsHTMLBeforeMutation(ctx); err != nil {
		return err
	}
	record, err := s.verifyAnalyticsHTMLBuild(ctx, id)
	if err != nil {
		return err
	}
	paths := txs.analyticsHTMLConfigurationPaths()
	for _, path := range paths {
		if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
			return err
		}
	}
	backups := make([]fileBackup, len(paths))
	for i, path := range paths {
		backups[i], err = txs.analyticsHTMLStableBackup(path)
		if err != nil {
			return err
		}
	}
	if !backups[0].existed {
		return errors.New("Nginx 原主配置不存在，不创建替代配置")
	}
	if !backups[2].existed && backups[1].existed {
		return errors.New("存在未归属的 HTML 健康检查文件，不覆盖")
	}
	if backups[2].existed {
		var old analyticsHTMLEngineIdentity
		if err := readAnalyticsHTMLPrivateJSON(paths[2], 64<<10, &old); err != nil {
			return err
		}
		if old.JobID == id {
			// Lost reply/replay: real worker acknowledgment is still mandatory.
			return s.requireAnalyticsHTMLReady(ctx)
		}
		if err := s.requireAnalyticsHTMLReady(ctx); err != nil {
			return err
		}
	}
	main, err := renderAnalyticsHTMLLoader(string(backups[0].data), id, true)
	if err != nil {
		return err
	}
	main, err = renderAnalyticsHTMLHealthMount(main, true)
	if err != nil {
		return err
	}
	health, err := analyticsHTMLHealthConfiguration(id)
	if err != nil {
		return err
	}
	identity := record.analyticsHTMLEngineIdentity
	identity.State = "active"
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	values := [][]byte{[]byte(main), []byte(health), append(data, '\n')}
	plan := make([]wafConfigChange, len(paths))
	for i, b := range backups {
		owner := b.owner
		if owner == nil {
			owner = &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		}
		mode := os.FileMode(0644)
		if i == 0 {
			mode = b.mode
		}
		if i == 2 {
			mode = 0600
		}
		plan[i] = wafConfigChange{Path: b.path, OldData: b.data, OldExists: b.existed, OldMode: b.mode, OldOwner: b.owner, NextData: values[i], NextExists: true, NextMode: mode, NextOwner: owner}
	}
	// Old syntax must already be valid; selecting a new optional engine cannot
	// become permission to repair unknown administrator configuration.
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	if _, err := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return err
	}
	return txs.applyAnalyticsHTMLPlanned(ctx, plan, identity)
}
