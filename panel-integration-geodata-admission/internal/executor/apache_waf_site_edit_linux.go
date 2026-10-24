//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

// Metadata-only website edits retain their installed application version and
// policy. This does not enable the separately signed native-body capability.
func apacheMetadataSitePolicy(content string, cfg core.WAFConfig, version, module string) (string, string, error) {
	switch version {
	case core.ApacheWAFVersion, "2.2.0", "2.1.0", "2.0.0", "1.0":
	default:
		return "", "", errors.New("Apache 元数据防护版本未知；网站修改不能隐式升级应用")
	}
	if _, err := core.DecodeApacheWAFConfig(core.WAFSettings(cfg)); err != nil {
		return "", "", err
	}
	if strings.Contains(content, "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.MatchString(content) {
		return "", "", errors.New("Apache 元数据网站不能接管未知原生模块或请求体挂载")
	}
	prepared, err := prepareApacheWAFTrustedProxySource(content, cfg.TrustedProxy, module)
	if err != nil {
		return "", "", err
	}
	bindings, err := apacheWAFBindings(prepared)
	if err != nil || len(bindings) == 0 {
		return "", "", errors.New("Apache 元数据防护缺少完整网站绑定")
	}
	rules, err := renderApacheWAFVersion(cfg, bindings, version)
	return prepared, rules, err
}

func apacheMetadataSiteBackupSame(before, after fileBackup) bool {
	return before.path == after.path && before.existed && after.existed && before.mode == after.mode && before.owner != nil && after.owner != nil && *before.owner == *after.owner && bytes.Equal(before.data, after.data)
}

// Older trusted-proxy installation inserted the exact owned remoteip LoadModule
// after the managed header; the website renderer emits it with the other global
// modules. That one relocation is not a site/policy edit. Keep the ORIGINAL
// validated live source instead of rewriting it and incrementing the policy.
// Every other byte, module identity and all virtual-host contents must match.
func apacheMetadataSiteSourceSame(candidate, original string, cfg core.WAFConfig, module string) bool {
	if candidate == original {
		return true
	}
	line := "LoadModule remoteip_module " + strconv.Quote(module) + "\n"
	without := func(source string) (string, bool) {
		checked, err := prepareApacheWAFTrustedProxySource(source, cfg.TrustedProxy, module)
		if err != nil || checked != source || strings.Count(source, line) != 1 {
			return "", false
		}
		at, host := strings.Index(source, line), strings.Index(source, "<VirtualHost")
		if at < len("# managed by panel\n") || source[at-1] != '\n' || host < 0 || at >= host {
			return "", false
		}
		return source[:at] + source[at+len(line):], true
	}
	a, aOK := without(candidate)
	b, bOK := without(original)
	return aOK && bOK && a == b
}

// The outer website transaction holds the original Apache WAF flock for its
// whole apply and compensation interval. Restarting Apache inside that lock
// runs ExecStartPre in another process, which correctly refuses the same lock.
// An actual Apache change requires a running verified installation and uses
// graceful reload. An independently validated, byte-identical Apache plan is
// not an Apache change: preserve its complete triplet and stopped/running
// choice without querying, starting or reloading an unrelated service.
func (s *Service) applyApacheWAFMetadataSites(ctx context.Context, content string, count int, add func(string)) (func() error, bool, error) {
	txs := s.apacheWAFTransactionService()
	paths := txs.apacheWAFConfigurationPaths()
	manifest, err := txs.apacheWAFStableBackup(paths[2])
	if errors.Is(err, os.ErrNotExist) || err == nil && !manifest.existed {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if _, err := apacheBodySiteManifestDocument(manifest.data); err != nil {
		return nil, true, err
	}
	var installed struct {
		ID       string         `json:"id"`
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(manifest.data, &installed); err != nil || installed.ID != "apache-waf" {
		return nil, true, errors.New("Apache 元数据防护安装身份无法核对，未修改网站")
	}
	if installed.Version == core.ApacheWAFNativeBodyVersion {
		return nil, true, errors.New("原生 Apache 请求体安装必须使用独立已核验的网站事务")
	}
	if count == 0 {
		return nil, true, errors.New("请先停用并移除 Apache 防护的站点策略，再停止最后一个受管网站")
	}
	cfg, err := core.DecodeApacheWAFConfig(installed.Settings)
	if err != nil {
		return nil, true, err
	}
	if _, err := os.Lstat(txs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return nil, true, errors.New("Apache 防护有未完成或不可核对的事务，未覆盖网站")
	}
	backups := []fileBackup{}
	for _, path := range paths {
		backup, err := txs.apacheWAFStableBackup(path)
		if err != nil || !backup.existed {
			return nil, true, errors.New("Apache 元数据防护的完整三文件缺失或不可核对")
		}
		backups = append(backups, backup)
	}
	if !bytes.Equal(manifest.data, backups[2].data) {
		return nil, true, errors.New("Apache 安装记录在网站准备期间变化，未修改")
	}
	release, err := apacheRelease()
	if err != nil {
		return nil, true, err
	}
	module := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	oldSource := string(backups[0].data)
	domain, err := apacheWAFConfigurationFilesMatchVersion(oldSource, cfg, module, paths[1], installed.Version)
	if err != nil {
		return nil, true, err
	}
	prepared, rules, err := apacheMetadataSitePolicy(content, cfg, installed.Version, module)
	if err != nil {
		return nil, true, err
	}
	for _, before := range backups {
		after, err := txs.apacheWAFStableBackup(before.path)
		if err != nil || !apacheMetadataSiteBackupSame(before, after) {
			return nil, true, errors.New("Apache 防护文件在只读核对期间变化，未覆盖网站")
		}
	}
	// Nginx-only edits do not change the Apache virtual hosts. Preserve the
	// entire triplet and live process rather than restart an unrelated service.
	if apacheMetadataSiteSourceSame(prepared, oldSource, cfg, module) && rules == string(backups[1].data) {
		add("Apache 网站配置与防护策略未变化；保留完整三文件和原服务启停状态，不调用或重启无关服务")
		return func() error { return nil }, true, nil
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")
	if err != nil || strings.TrimSpace(state) != "active" {
		return nil, true, errors.New("Apache 防护服务未运行；未在网站事务锁内隐式启动或覆盖配置")
	}
	if err := apacheWAFWaitLoadedVersion(ctx, cfg, domain, installed.Version); err != nil {
		return nil, true, err
	}
	next := cfg
	next.Policy.Revision++
	prepared, rules, err = apacheMetadataSitePolicy(content, next, installed.Version, module)
	if err != nil {
		return nil, true, err
	}
	updated, err := apacheBodySiteManifest(manifest.data, next)
	if err != nil {
		return nil, true, err
	}
	plan, err := txs.planApacheWAFTransaction(backups, prepared, rules, updated, false)
	if err != nil {
		return nil, true, err
	}
	verify := func(ctx context.Context, cfg core.WAFConfig, source string) error {
		domain, err := apacheWAFConfigurationFilesMatchVersion(source, cfg, module, paths[1], installed.Version)
		if err != nil {
			return err
		}
		return apacheWAFWaitLoadedVersion(ctx, cfg, domain, installed.Version)
	}
	if err := txs.applyApacheWAFPlanned(ctx, plan, func(ctx context.Context) error { return verify(ctx, next, prepared) }, add); err != nil {
		return nil, true, err
	}
	rollback := func() error {
		bounded, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := os.Lstat(txs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Apache 补偿存在未完成或不可核对的事务，保留证据")
		}
		reverse := make([]wafConfigChange, len(plan))
		for i, change := range plan {
			match, err := txs.wafCurrentMatches(change, true)
			if err != nil || !match {
				return errors.New("Apache 网站补偿时文件已被外部修改，未覆盖")
			}
			reverse[i] = wafConfigChange{Path: change.Path, OldData: change.NextData, OldExists: change.NextExists, OldMode: change.NextMode, OldOwner: change.NextOwner, NextData: change.OldData, NextExists: change.OldExists, NextMode: change.OldMode, NextOwner: change.OldOwner}
		}
		return txs.applyApacheWAFPlanned(bounded, reverse, func(ctx context.Context) error { return verify(ctx, cfg, oldSource) }, add)
	}
	add("Apache 元数据防护随网站变更保存完整三文件事务；保留应用版本、可信代理和规则，平滑重载与实际修订指纹已核对")
	return rollback, true, nil
}
