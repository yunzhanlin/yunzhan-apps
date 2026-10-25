//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"local/panel/internal/core"
)

// This is a fixed root startup check, not an application install or enable.
// An actual independently sealed engine and the committed three-file policy
// are required before recreating only missing site leaves on the bounded
// cache mounted by PID1. No HTTP/API caller selects a path or mount option.
func PrepareApacheBodyRuntime() error {
	if os.Geteuid() != 0 {
		return errors.New("Apache 请求体启动准备只能由 root 执行")
	}
	s := nativeWAFService()
	manifest := s.apacheWAFTransactionService().apacheWAFConfigurationPaths()[2]
	if _, err := os.Lstat(manifest); errors.Is(err, os.ErrNotExist) {
		return s.apacheBodyNoOrphanSource()
	} else if err != nil {
		return err
	}
	lock, err := s.apacheWAFTransactionService().lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return s.prepareApacheBodyCommittedRuntime(ctx)
}

func (s *Service) apacheBodyNoOrphanSource() error {
	source, err := apacheWAFReadStableFile(s.Config.ApacheSiteConfig, 2<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.Contains(string(source), "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.Match(source) {
		return errors.New("Apache 原生挂载没有对应有效安装策略，未启动或清除")
	}
	return nil
}

func (s *Service) prepareApacheBodyCommittedRuntime(ctx context.Context) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || s.Config.ApacheSiteConfig != "/etc/panel/apache/httpd.conf" || os.Geteuid() != 0 {
		return errors.New("Apache 启动只核验固定真实受管目录")
	}
	if err := s.apacheNativeBodyNoPending(); err != nil {
		return err
	}
	txs := s.apacheWAFTransactionService()
	paths := txs.apacheWAFConfigurationPaths()
	manifest, err := txs.apacheWAFStableBackup(paths[2])
	if err != nil {
		return err
	}
	if !manifest.existed {
		return s.apacheBodyNoOrphanSource()
	}
	if _, err := apacheBodySiteManifestDocument(manifest.data); err != nil {
		return err
	}
	var installed struct {
		ID       string         `json:"id"`
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(manifest.data, &installed); err != nil || installed.ID != "apache-waf" {
		return errors.New("Apache 防护启动安装身份不可核实")
	}
	if installed.Version != core.ApacheWAFNativeBodyVersion {
		if installed.Version != core.ApacheWAFVersion && installed.Version != "2.2.0" && installed.Version != "2.1.0" && installed.Version != "2.0.0" && installed.Version != "1.0" {
			return errors.New("Apache 防护启动版本未知，未猜测或启动模块")
		}
		if body, exists := installed.Settings["body"]; exists && body != nil {
			return errors.New("Apache 旧版安装记录不能声明原生启动能力")
		}
		return s.apacheBodyNoOrphanSource()
	}
	cfg, err := core.DecodeApacheWAFNativeBodyConfig(installed.Settings)
	if err != nil {
		return err
	}
	backups := []fileBackup{}
	for _, path := range paths {
		b, err := txs.apacheWAFStableBackup(path)
		if err != nil || !b.existed {
			return errors.New("Apache 原生启动完整配置三文件缺失或不能核验")
		}
		backups = append(backups, b)
	}
	if string(manifest.data) != string(backups[2].data) {
		return errors.New("Apache 原生启动安装记录读取期间变化")
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	if _, err := apacheWAFConfigurationFilesMatchVersion(string(backups[0].data), cfg, filepath.Join(release.Prefix(), "modules/mod_remoteip.so"), paths[1], core.ApacheWAFNativeBodyVersion); err != nil {
		return err
	}
	if err := s.verifyApacheBodyTransition(ctx, cfg, cfg); err != nil {
		return err
	}
	if err := s.prepareApacheBodyStorage(ctx, cfg); err != nil {
		return err
	}
	for _, before := range backups {
		after, err := txs.apacheWAFStableBackup(before.path)
		if err != nil || before.existed != after.existed || before.mode != after.mode || string(before.data) != string(after.data) || before.owner == nil || after.owner == nil || *before.owner != *after.owner {
			return errors.New("Apache 原生启动配置在准备期间变化，未加载模块")
		}
	}
	return ctx.Err()
}
