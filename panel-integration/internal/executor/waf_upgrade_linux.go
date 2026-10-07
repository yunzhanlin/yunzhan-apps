//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"local/panel/internal/core"
)

// An old disabled URL-CC record may refer to a site already archived by an
// older panel. Preserve that exact inert historical policy on version upgrade;
// never create a website, silently delete the record or activate its rule.
// All other references must still resolve to a regular managed site config.
// Normal policy edits continue to use the stricter prepareWAFSettings path.
func wafHistoricalVersionValid(version string, cfg core.WAFConfig) bool {
	return version == core.WAFVersion || version == "2.0.1" && cfg.Body == nil || version == "2.1.0"
}

func (s *Service) wafLegacyMigrationReferences(cfg core.WAFConfig) error {
	required, disabledCC := map[string]bool{}, map[string]bool{}
	if cfg.Body != nil {
		for _, site := range cfg.Body.Sites {
			required[site.SiteID] = true
		}
	}
	for _, site := range cfg.Policy.Sites {
		required[site.SiteID] = true
	}
	for _, entries := range cfg.Policy.Lists {
		for _, entry := range entries {
			required[entry.SiteID] = true
		}
	}
	for _, rule := range cfg.Policy.Rules {
		required[rule.SiteID] = true
	}
	for _, rule := range cfg.Policy.CCRules {
		if rule.Enabled {
			required[rule.SiteID] = true
		} else {
			disabledCC[rule.SiteID] = true
		}
	}
	for _, id := range core.WAFScopedSites(cfg) {
		path := filepath.Join(s.Config.ConfDir, id+".conf")
		if err := ordinary(path, false); err != nil {
			if errors.Is(err, os.ErrNotExist) && disabledCC[id] && !required[id] {
				continue
			}
			return errors.New("WAF 历史迁移存在启用中的缺失网站或异常配置路径，未开始写入")
		}
		if err := ownedRuntimePath(path, false); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > wafTransactionBytes || !strings.HasPrefix(string(data), "# managed by panel; site="+id) {
			return errors.New("WAF 历史迁移引用的配置不属于受管网站")
		}
	}
	return nil
}

func (s *Service) upgradeWAFLegacy(ctx context.Context, add func(string)) error {
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	unlock, err := s.lockRuntimeUse()
	if err != nil {
		return err
	}
	defer unlock()
	// Re-check under the same lock used by website and WAF mutations. A
	// queued task must not rely on the health snapshot from job submission.
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || (manifest.Version != "2.0.1" && manifest.Version != "2.1.0") {
		return errors.New("WAF 历史迁移版本已变化，请刷新核对")
	}
	status := s.softwareStatusWithWAFLock(ctx, "nginx-waf", lock)
	if !status.Installed || !status.Healthy {
		return errors.New("WAF 旧版实际配置或生效指纹核对失败，未开始迁移")
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	if !wafHistoricalVersionValid(manifest.Version, cfg) {
		return errors.New("WAF 历史版本或请求体来源不可验证")
	}
	if err := s.wafLegacyMigrationReferences(cfg); err != nil {
		return err
	}
	cfg.Policy.Revision++
	return s.applyWAFTransactionChecked(ctx, cfg, false, nginx, add, &manifest)
}

// Bind every old byte in the final transaction to the independently verified
// old render, not merely to whatever happened to be on disk at plan time.
// Only the two metadata includes and their manifest may change in this
// migration. A concurrent external edit is rejected before creating backups
// or replacing any active file.
func (s *Service) verifyWAFLegacyUpgradePlan(manifest softwareManifest, cfg core.WAFConfig, changes []wafConfigChange) error {
	old, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || (manifest.Version != "2.0.1" && manifest.Version != "2.1.0") || !wafHistoricalVersionValid(manifest.Version, old) || cfg.Policy.Revision != old.Policy.Revision+1 {
		return errors.New("WAF 历史迁移身份或修订号异常")
	}
	expected := old
	expected.Policy.Revision++
	want, _ := json.Marshal(expected)
	actual, _ := json.Marshal(cfg)
	if !bytes.Equal(want, actual) {
		return errors.New("WAF 版本迁移不能改变现有策略")
	}
	if err := s.wafLegacyMigrationReferences(old); err != nil {
		return err
	}
	h, v := wafFiles(s)
	http, server := renderWAFPolicyVersion(old, manifest.Version)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	files := map[string][]byte{h: []byte(http), v: []byte(server), s.softwareManifestPath("nginx-waf"): data}
	if len(changes) != len(files) {
		return errors.New("WAF 版本迁移出现额外配置变化，未开始修改")
	}
	seen := map[string]bool{}
	for _, change := range changes {
		want, ok := files[change.Path]
		mode := os.FileMode(0640)
		if change.Path == s.softwareManifestPath("nginx-waf") {
			mode = 0600
		}
		if !ok || seen[change.Path] || !change.OldExists || !change.NextExists || change.OldMode != mode || change.NextMode != mode || !bytes.Equal(want, change.OldData) {
			return errors.New("WAF 历史规则、清单或权限在迁移前被修改，未开始写入")
		}
		seen[change.Path] = true
	}
	return nil
}
