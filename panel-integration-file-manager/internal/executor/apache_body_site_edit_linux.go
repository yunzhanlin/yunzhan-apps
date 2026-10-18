//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"local/panel/internal/core"
)

// The website job already holds lockApacheWAFSiteMutation across all its
// coupled Nginx/PHP/Apache changes and compensation. Do not acquire a second
// flock or copy the Service mutex here. This branch is only for the distinct
// future native-body application identity; old installations do not gain it.
func (s *Service) applyApacheNativeBodySites(ctx context.Context, content string, count int, add func(string)) (func() error, bool, error) {
	txs := s.apacheWAFTransactionService()
	paths := txs.apacheWAFConfigurationPaths()
	if _, err := os.Lstat(paths[2]); errors.Is(err, os.ErrNotExist) {
		// Missing installation does not authorize erasing an orphaned native
		// block. Ordinary first-time websites otherwise keep their old path.
		if source, err := apacheWAFReadStableFile(paths[0], 2<<20); err == nil && (strings.Contains(string(source), "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.Match(source)) {
			return nil, true, errors.New("Apache 含无安装记录的请求体挂载，未覆盖网站")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, true, err
		}
		return nil, false, nil
	} else if err != nil {
		return nil, true, err
	}
	manifest, err := txs.apacheWAFStableBackup(paths[2])
	if err != nil {
		return nil, true, err
	}
	if !manifest.existed {
		return nil, false, nil
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
		return nil, true, errors.New("Apache 防护安装身份不可核实，未覆盖网站")
	}
	if installed.Version != core.ApacheWAFNativeBodyVersion {
		if installed.Version != core.ApacheWAFVersion && installed.Version != "2.2.0" && installed.Version != "2.1.0" && installed.Version != "2.0.0" && installed.Version != "1.0" {
			return nil, true, errors.New("Apache 防护安装版本未知，未猜测或覆盖网站")
		}
		if body, exists := installed.Settings["body"]; exists && body != nil {
			return nil, true, errors.New("未知或元数据旧版不能接管原生请求体策略，未覆盖网站")
		}
		source, err := apacheWAFReadStableFile(paths[0], 2<<20)
		if err == nil && (strings.Contains(string(source), "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.Match(source)) {
			return nil, true, errors.New("Apache 元数据安装记录与原生挂载矛盾，未覆盖网站")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, true, err
		}
		return nil, false, nil
	}
	if count == 0 {
		return nil, true, errors.New("请先停用并移除 Apache 防护的站点策略，再停止最后一个受管网站")
	}
	cfg, err := core.DecodeApacheWAFNativeBodyConfig(installed.Settings)
	if err != nil {
		return nil, true, err
	}
	// The explicit pending-path absence check below also refuses inaccessible or
	// malformed journals; an unreadable record is never interpreted as absent.
	if err := s.apacheNativeBodyNoPending(); err != nil {
		return nil, true, err
	}
	backups := []fileBackup{}
	for _, path := range paths {
		backup, err := txs.apacheWAFStableBackup(path)
		if err != nil {
			return nil, true, err
		}
		backups = append(backups, backup)
	}
	if string(backups[2].data) != string(manifest.data) {
		return nil, true, errors.New("Apache 安装记录在网站准备期间变化，未修改")
	}
	release, err := apacheRelease()
	if err != nil {
		return nil, true, err
	}
	module := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	oldSource := string(backups[0].data)
	domain, err := apacheWAFConfigurationFilesMatchVersion(oldSource, cfg, module, paths[1], core.ApacheWAFNativeBodyVersion)
	if err != nil {
		return nil, true, err
	}
	if err := s.verifyApacheBodyTransition(ctx, cfg, cfg); err != nil {
		return nil, true, err
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")
	if err != nil || strings.TrimSpace(state) != "active" {
		return nil, true, errors.New("Apache 原生防护实际服务未运行，未覆盖或隐式启动网站")
	}
	if err := apacheWAFWaitLoadedVersion(ctx, cfg, domain, core.ApacheWAFNativeBodyVersion); err != nil {
		return nil, true, err
	}
	next := cfg
	// A site edit changes the complete loaded configuration. Persist a new
	// revision so the actual response oracle distinguishes a stale generation
	// even when the body policy and its immutable program remain unchanged.
	next.Policy.Revision++
	prepared, err := prepareApacheWAFTrustedProxySource(content, next.TrustedProxy, module)
	if err != nil {
		return nil, true, err
	}
	prepared, err = s.prepareApacheBodyTransition(ctx, prepared, core.DefaultApacheWAFConfig(), next)
	if err != nil {
		return nil, true, err
	}
	bindings, err := apacheWAFBindings(prepared)
	if err != nil {
		return nil, true, err
	}
	rules, err := renderApacheWAFVersion(next, bindings, core.ApacheWAFNativeBodyVersion)
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
		if err := s.verifyApacheBodyTransition(ctx, cfg, cfg); err != nil {
			return err
		}
		domain, err := apacheWAFConfigurationFilesMatchVersion(source, cfg, module, paths[1], core.ApacheWAFNativeBodyVersion)
		if err != nil {
			return err
		}
		return apacheWAFWaitLoadedVersion(ctx, cfg, domain, core.ApacheWAFNativeBodyVersion)
	}
	if err := txs.applyApacheWAFPlanned(ctx, plan, func(ctx context.Context) error { return verify(ctx, next, prepared) }, add); err != nil {
		return nil, true, err
	}
	rollback := func() error {
		bounded, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.apacheNativeBodyNoPending(); err != nil {
			return err
		}
		reverse := make([]wafConfigChange, len(plan))
		for i, change := range plan {
			match, err := txs.wafCurrentMatches(change, true)
			if err != nil || !match {
				return errors.New("Apache 网站补偿时配置已被外部修改，未覆盖当前文件")
			}
			reverse[i] = wafConfigChange{Path: change.Path, OldData: change.NextData, OldExists: change.NextExists, OldMode: change.NextMode, OldOwner: change.NextOwner, NextData: change.OldData, NextExists: change.OldExists, NextMode: change.OldMode, NextOwner: change.OldOwner}
		}
		return txs.applyApacheWAFPlanned(bounded, reverse, func(ctx context.Context) error { return verify(ctx, cfg, oldSource) }, add)
	}
	add("原生 Apache 防护随网站变更保存完整三文件事务；程序与站点策略保留，平滑重载和新修订指纹已核对")
	return rollback, true, nil
}

// Preserve extension fields from the installation record. A website edit is
// not an application reinstall and must not silently discard provenance or
// future receipt metadata. Only the policy and its modification time change.
func apacheBodySiteManifest(data []byte, cfg core.WAFConfig) (map[string]json.RawMessage, error) {
	document, err := apacheBodySiteManifestDocument(data)
	if err != nil {
		return nil, err
	}
	settings, err := json.Marshal(core.WAFSettings(cfg))
	if err != nil {
		return nil, err
	}
	updatedAt, err := json.Marshal(core.Now())
	if err != nil {
		return nil, err
	}
	document["settings"], document["updated_at"] = settings, updatedAt
	return document, nil
}

func apacheBodySiteManifestDocument(data []byte) (map[string]json.RawMessage, error) {
	if err := apacheBodyValidateJSON(data, 512<<10, 32768, 16, nil); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("Apache 安装记录不是完整对象，未覆盖网站")
	}
	document := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, valid := token.(string)
		if err != nil || !valid {
			return nil, errors.New("Apache 安装记录字段损坏，未覆盖网站")
		}
		if _, duplicate := document[key]; duplicate {
			return nil, errors.New("Apache 安装记录存在重复字段，未猜测或覆盖网站")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		document[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("Apache 安装记录不完整，未覆盖网站")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("Apache 安装记录存在尾随内容，未覆盖网站")
	}
	for _, key := range []string{"id", "version", "settings"} {
		if _, exists := document[key]; !exists {
			return nil, errors.New("Apache 安装记录缺少准确的小写身份字段，未覆盖网站")
		}
	}
	return document, nil
}

func (s *Service) apacheNativeBodyNoPending() error {
	_, err := os.Lstat(s.apacheWAFTransactionService().wafPendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("Apache 原生防护有未完成事务，保留证据且未覆盖网站")
}
