//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const wafTransactionBytes = 8 << 20

type wafConfigChange struct {
	Path       string      `json:"path"`
	OldData    []byte      `json:"old_data"`
	OldExists  bool        `json:"old_exists"`
	OldMode    os.FileMode `json:"old_mode"`
	NextData   []byte      `json:"next_data"`
	NextExists bool        `json:"next_exists"`
	NextMode   os.FileMode `json:"next_mode"`
}

// A complete, bounded plan is built without writing any configuration. The
// persistent transaction includes every before/after byte and permission,
// including the manifest, before the first replacement can take place.
func (s *Service) planWAFConfiguration(cfg core.WAFConfig, uninstall bool) ([]wafConfigChange, error) {
	return s.planWAFConfigurationVersion(cfg, uninstall, core.WAFVersion)
}

func (s *Service) planWAFConfigurationVersion(cfg core.WAFConfig, uninstall bool, version string) ([]wafConfigChange, error) {
	if !wafHistoricalVersionValid(version, cfg) {
		return nil, errors.New("WAF 历史版本不支持严格迁移核对")
	}
	var err error
	cfg, err = core.DecodeWAFConfig(core.WAFSettings(cfg))
	if err != nil {
		return nil, err
	}
	if !uninstall {
		if err := core.ValidateWAFBodyLogRotationSource(cfg); err != nil {
			return nil, err
		}
	}
	var previous core.WAFConfig
	previousVersion := ""
	if manifest, err := s.readSoftwareManifest("nginx-waf"); err == nil {
		previousVersion = manifest.Version
		previous, err = core.DecodeWAFConfig(manifest.Settings)
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	active := map[string]wafBodyPolicy{}
	if cfg.Body != nil && !uninstall {
		for _, site := range cfg.Body.Sites {
			if policy, on := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); on {
				active[site.SiteID] = policy
			}
		}
	}
	changes := map[string]wafConfigChange{}
	total := 0
	read := func(path string) (fileBackup, error) {
		if st, err := os.Lstat(path); err == nil && st.Size() > int64(wafTransactionBytes-total) {
			return fileBackup{}, errors.New("WAF 配置计划超过 8 MiB，未开始修改")
		}
		b, err := backupFile(path)
		if err != nil {
			return b, err
		}
		total += len(b.data)
		if total > wafTransactionBytes {
			return b, errors.New("WAF 配置计划超过 8 MiB，未开始修改")
		}
		return b, nil
	}
	put := func(b fileBackup, data []byte, exists bool, mode os.FileMode) error {
		if b.existed == exists && bytes.Equal(b.data, data) && (!exists || b.mode == mode) {
			return nil
		}
		total += len(data)
		if total > wafTransactionBytes {
			return errors.New("WAF 配置计划和恢复数据超过 8 MiB，未开始修改")
		}
		if _, exists := changes[b.path]; exists {
			return errors.New("WAF 配置计划出现重复路径")
		}
		changes[b.path] = wafConfigChange{b.path, b.data, b.existed, b.mode, data, exists, mode}
		return nil
	}
	main, err := read(s.Config.NginxConf)
	if err != nil || !main.existed {
		return nil, errors.New("Nginx 主配置不可读取，未开始修改")
	}
	engineJob := ""
	if cfg.Body != nil {
		engineJob = cfg.Body.EngineJobID
	}
	content, err := renderWAFBodyLoader(string(main.data), engineJob, len(active) > 0)
	if err != nil {
		return nil, err
	}
	if !uninstall {
		content, err = ensureLineAfter(content, "http {\n", "  include /etc/panel/waf/http.d/*.conf;\n", false)
		if err != nil {
			return nil, err
		}
	}
	if err := put(main, []byte(content), true, main.mode); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Config.ConfDir)
	if err != nil || len(entries) > 4096 {
		return nil, errors.New("网站配置目录不可读取或条目超过 4096")
	}
	found := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".conf")
		if !core.ValidID(id) {
			continue // Never take ownership of another application's config.
		}
		b, err := read(filepath.Join(s.Config.ConfDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(string(b.data), "# managed by panel; site="+id) {
			if _, on := active[id]; on {
				return nil, errors.New("请求体防护网站配置不属于云栈")
			}
			continue
		}
		_, bodyOn := active[id]
		if wafCCObservationVersion(previousVersion) && strings.Contains(string(b.data), wafCCSiteBegin) {
			expected := wafCCSiteBegin + wafCCSiteLines(wafEffectiveMetadataMode(previous, id)) + wafCCSiteEnd
			if strings.Count(string(b.data), expected) != strings.Count(string(b.data), "server {\n") {
				return nil, errors.New("网站 CC 模式与已保存策略不符，未开始覆盖")
			}
		}
		content, err := renderWAFBodySite(string(b.data), id, false)
		if err != nil {
			return nil, err
		}
		found[id] = true
		first := strings.SplitN(content, "\n", 2)[0]
		if !uninstall && !strings.Contains(first, "panel-waf-disabled") && strings.Contains(content, "server {\n") {
			include := "  include /etc/panel/waf/server.d/*.conf;\n"
			line := "  set $panel_waf_site " + id + ";\n" + include
			if strings.Contains(content, include) && !strings.Contains(content, line) {
				content = strings.ReplaceAll(content, include, line)
			} else {
				content, err = ensureLineAfter(content, "server {\n", line, true)
			}
			if err != nil {
				return nil, err
			}
		}
		// A stopped or explicitly opted-out website has no active body
		// directives. Retain its selected engine and generated policy so a
		// subsequent website re-enable can validate and restore protection.
		if bodyOn && !strings.Contains(first, "panel-waf-disabled") && !strings.Contains(first, "; disabled") && strings.Contains(content, "server {\n") {
			content, err = renderWAFBodySite(content, id, true)
			if err != nil {
				return nil, err
			}
		}
		if wafCCObservationVersion(version) {
			content, err = renderWAFCCSite(content, id, wafEffectiveMetadataMode(cfg, id), !uninstall)
			if err != nil {
				return nil, err
			}
			if !uninstall && wafEffectiveMetadataMode(cfg, id) == "observe" && strings.Contains(content, wafCCSiteBegin) {
				if err := s.verifyWAFCCObservationIncludes(); err != nil {
					return nil, err
				}
			}
		}
		if err := put(b, []byte(content), true, b.mode); err != nil {
			return nil, err
		}
	}
	for id := range active {
		if !found[id] {
			return nil, errors.New("请求体防护网站已不存在，未开始修改")
		}
	}
	httpPath, serverPath := wafFiles(s)
	httpConfig, serverConfig := renderWAFPolicyVersion(cfg, version)
	const metadataConfig = "# managed by panel; native-waf-metadata-only\nmodsecurity_metadata_log /var/lib/panel-waf/body-events.log;\n"
	const legacyMetadataConfig = "# managed by panel; native-waf-metadata-only\nmodsecurity_metadata_log /var/log/nginx/panel-waf-body-events.log;\n"
	for _, item := range []struct{ path, text string }{{httpPath, httpConfig}, {serverPath, serverConfig}, {s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf"), metadataConfig}} {
		b, err := read(item.path)
		if err != nil {
			return nil, err
		}
		exists := !uninstall && (item.path != s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf") || len(active) > 0)
		var data []byte
		if exists {
			data = []byte(item.text)
		}
		if item.path == s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf") && b.existed && string(b.data) != item.text && string(b.data) != legacyMetadataConfig {
			return nil, errors.New("请求体防护日志配置被外部修改，未开始覆盖")
		}
		if err := put(b, data, exists, 0640); err != nil {
			return nil, err
		}
	}
	bodyDir := s.systemPath("/etc/panel/waf/body.d")
	paths := map[string]bool{}
	if entries, err := os.ReadDir(bodyDir); err == nil {
		if len(entries) > 64 {
			return nil, errors.New("请求体规则目录超过 64 条")
		}
		for _, entry := range entries {
			id := strings.TrimSuffix(entry.Name(), ".conf")
			if !core.ValidID(id) || entry.Name() != id+".conf" {
				return nil, errors.New("请求体规则目录存在未知文件，拒绝接管")
			}
			paths[id] = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for id := range active {
		paths[id] = true
	}
	for id := range paths {
		b, err := read(filepath.Join(bodyDir, id+".conf"))
		if err != nil {
			return nil, err
		}
		if b.existed {
			oldPolicy, on := core.WAFEffectiveBodyPolicy(previous, id)
			if !on || previous.Body == nil {
				return nil, errors.New("已有请求体规则未登记在当前清单中，拒绝覆盖")
			}
			expected, err := wafBodyPolicyFile(oldPolicy, id, previous.Body.EngineJobID)
			if err != nil || string(b.data) != expected {
				return nil, errors.New("网站请求体规则被外部修改，拒绝覆盖")
			}
		}
		policy, on := active[id]
		var data []byte
		if on {
			text, err := wafBodyPolicyFile(policy, id, engineJob)
			if err != nil {
				return nil, err
			}
			data = []byte(text)
		}
		if err := put(b, data, on, 0640); err != nil {
			return nil, err
		}
	}
	manifestPath := s.softwareManifestPath("nginx-waf")
	b, err := read(manifestPath)
	if err != nil {
		return nil, err
	}
	var data []byte
	if !uninstall {
		manifest := softwareManifest{ID: "nginx-waf", Version: version, Settings: core.WAFSettings(cfg), InstalledAt: core.Now()}
		if old, err := s.readSoftwareManifest("nginx-waf"); err == nil {
			manifest.InstalledAt = old.InstalledAt
		}
		data, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, err
		}
		data = append(data, '\n')
	}
	if err := put(b, data, !uninstall, 0600); err != nil {
		return nil, err
	}
	out := make([]wafConfigChange, 0, len(changes))
	for _, c := range changes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		// Commit the settings only after the live Nginx rules were verified.
		if out[i].Path == manifestPath || out[j].Path == manifestPath {
			return out[j].Path == manifestPath
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}
