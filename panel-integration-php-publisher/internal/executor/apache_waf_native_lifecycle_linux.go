//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

func (s *Service) apacheNativeCurrent() (map[string]any, error) {
	record, err := s.moduleInstalledRecord("apache-waf")
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if _, err = apacheBodySiteManifestDocument(raw); err != nil {
		return nil, err
	}
	version, ok := record["version"].(string)
	if !ok || version != core.ApacheWAFVersion && version != core.ApacheWAFNativeBodyVersion {
		return nil, errors.New("Apache 原生版本仅接续完整2.3.0或2.4.0安装记录；先完成原签名迁移")
	}
	if _, ok := record["settings"].(map[string]any); !ok {
		return nil, errors.New("Apache 完整原配置缺失；未采用默认值替代")
	}
	return record, nil
}

func (s *Service) apacheNativeSettings(raw map[string]any, install, upgrading bool) (core.WAFConfig, error) {
	cfg, err := core.DecodeApacheWAFNativeBodyConfig(raw)
	if err != nil {
		return cfg, err
	}
	for _, name := range []string{"body", "trusted_proxy"} {
		if _, explicit := raw[name]; explicit && raw["policy"] == nil {
			return cfg, errors.New("Apache 原生及可信代理策略需要完整policy与当前修订号")
		}
	}
	current, err := s.apacheNativeCurrent()
	if errors.Is(err, os.ErrNotExist) {
		if !install {
			return cfg, errors.New("Apache 原生防护未安装，配置不能提升版本")
		}
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if install {
		return cfg, errors.New("Apache 应用已安装，不能以重新安装覆盖版本、策略或历史")
	}
	if current["version"] != core.ApacheWAFNativeBodyVersion && !upgrading {
		return cfg, errors.New("先使用应用商店签名升级至Apache2.4.0，配置保存不授予请求体能力")
	}
	previous, err := core.DecodeApacheWAFVersionConfig(current["settings"].(map[string]any), current["version"].(string))
	if err != nil {
		return cfg, err
	}
	if len(raw) == 0 {
		return previous, nil
	}
	if _, ok := raw["policy"]; !ok {
		profile, rate := cfg.Profile, cfg.Rate
		cfg = previous
		cfg.Profile, cfg.Rate = profile, rate
	} else {
		if cfg.Policy.Revision != previous.Policy.Revision {
			return cfg, errors.New("Apache 配置修订已变化；刷新核对，不覆盖原策略")
		}
		if _, ok := raw["body"]; !ok {
			cfg.Body = previous.Body
		}
		if _, ok := raw["trusted_proxy"]; !ok {
			cfg.TrustedProxy = previous.TrustedProxy
		}
	}
	return core.DecodeApacheWAFNativeBodyConfig(core.WAFSettings(cfg))
}

func apacheNativeMetadataMounts(source string) string {
	return regexp.MustCompile("(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>").ReplaceAllStringFunc(source, func(block string) string {
		id := apacheBodySiteIdentity.FindStringSubmatch(block)
		if len(id) == 2 && !strings.Contains(block, "PANEL_AW_SITE="+id[1]) {
			block = strings.Replace(block, "\n", "\n  SetEnvIfExpr \"true\" PANEL_AW_SITE="+id[1]+"\n", 1)
		}
		if !strings.Contains(block, apacheWAFInclude) {
			block = strings.Replace(block, "\n", "\n  "+apacheWAFInclude, 1)
		}
		return block
	})
}

// Remove only canonical old body sections before applying the existing strict
// proxy planner; sealed CRS includes never become an arbitrary-include bypass.
func apacheNativeCandidate(source string, previous, next core.WAFConfig, module string) (string, string, error) {
	outside, err := transitionApacheBodySource(source, previous, core.DefaultApacheWAFConfig())
	if err != nil {
		return "", "", err
	}
	outside, err = prepareApacheWAFTrustedProxySource(outside, next.TrustedProxy, module)
	if err != nil {
		return "", "", err
	}
	prepared, err := transitionApacheBodySource(outside, core.DefaultApacheWAFConfig(), next)
	if err != nil {
		return "", "", err
	}
	prepared = apacheNativeMetadataMounts(prepared)
	bindings, err := apacheWAFBindings(prepared)
	if err != nil || len(bindings) == 0 {
		return "", "", errors.New("Apache 原生策略需要运行中的受管网站")
	}
	rules, err := renderApacheWAFVersion(next, bindings, core.ApacheWAFNativeBodyVersion)
	return prepared, rules, err
}

func (s *Service) confirmApacheNativeReplay(ctx context.Context, raw map[string]any) (bool, error) {
	if raw["policy"] == nil {
		return false, nil
	}
	current, err := s.apacheNativeCurrent()
	if err != nil || current["version"] != core.ApacheWAFNativeBodyVersion {
		return false, nil
	}
	wanted, err := core.DecodeApacheWAFNativeBodyConfig(current["settings"].(map[string]any))
	if err != nil {
		return false, err
	}
	cfg, err := core.DecodeApacheWAFNativeBodyConfig(raw)
	if err != nil || wanted.Policy.Revision != cfg.Policy.Revision+1 {
		return false, nil
	}
	if _, ok := raw["body"]; !ok {
		cfg.Body = wanted.Body
	}
	if _, ok := raw["trusted_proxy"]; !ok {
		cfg.TrustedProxy = wanted.TrustedProxy
	}
	cfg.Policy.Revision = wanted.Policy.Revision
	a, _ := json.Marshal(cfg)
	b, _ := json.Marshal(wanted)
	if !bytes.Equal(a, b) {
		return false, nil
	}
	if err = s.verifyApacheWAFHealth(ctx, core.ApacheWAFNativeBodyVersion, current["settings"].(map[string]any)); err != nil {
		return true, errors.New("Apache 原生原请求字节已提交但实际加载未核实，未重载、重写或冒充成功：" + err.Error())
	}
	return true, nil
}

// Separate entrypoint, reached only by a signed2.4 install/update or an exact
// current2.4 configuration. Metadata2.3 and direct legacy installation remain
// unchanged. The complete prior/next triplet is journaled before activation.
func (s *Service) applyApacheNativeWAF(ctx context.Context, raw map[string]any, install, upgrading bool, add func(string)) error {
	txs := s.apacheWAFTransactionService()
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = txs.recoverApacheWAFBeforeMutation(ctx); err != nil {
		return err
	}
	if !install && !upgrading {
		if replay, e := s.confirmApacheNativeReplay(ctx, raw); replay || e != nil {
			if e != nil {
				return e
			}
			add("原生Apache原任务修订、完整三文件、密封程序和实际加载均已核对；未重复写入或重载")
			return nil
		}
	}
	cfg, err := s.apacheNativeSettings(raw, install, upgrading)
	if err != nil {
		return err
	}
	paths := txs.apacheWAFConfigurationPaths()
	backups := []fileBackup{}
	for _, path := range paths {
		b, e := txs.apacheWAFStableBackup(path)
		if e != nil {
			return e
		}
		backups = append(backups, b)
	}
	if !backups[0].existed {
		return errors.New("Apache 完整配置缺失，未开始原生应用事务")
	}
	previous := core.DefaultApacheWAFConfig()
	installedAt := core.Now()
	if backups[2].existed {
		if install {
			return errors.New("Apache 原安装记录存在，拒绝安装覆盖")
		}
		if _, err = apacheBodySiteManifestDocument(backups[2].data); err != nil {
			return err
		}
		var old struct {
			ID          string         `json:"id"`
			Version     string         `json:"version"`
			Settings    map[string]any `json:"settings"`
			InstalledAt string         `json:"installed_at"`
		}
		if err = json.Unmarshal(backups[2].data, &old); err != nil || old.ID != "apache-waf" {
			return errors.New("Apache 原安装身份不可核对")
		}
		if old.Version != core.ApacheWAFNativeBodyVersion && !(upgrading && old.Version == core.ApacheWAFVersion) {
			return errors.New("Apache 原生版本转换不受支持，未修改")
		}
		previous, err = core.DecodeApacheWAFVersionConfig(old.Settings, old.Version)
		if err != nil {
			return err
		}
		if err = s.verifyApacheWAFHealth(ctx, old.Version, old.Settings); err != nil {
			return err
		}
		if old.InstalledAt != "" {
			installedAt = old.InstalledAt
		}
	} else if !install || backups[1].existed {
		return errors.New("Apache 原规则或安装身份矛盾，未接管孤立文件")
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	module := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	cfg.Policy.Revision++
	updated, rules, err := apacheNativeCandidate(string(backups[0].data), previous, cfg, module)
	if err != nil {
		return err
	}
	if err = s.verifyApacheBodyTransition(ctx, previous, cfg); err != nil {
		return err
	}
	if cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled {
		if err = verifyApacheWAFRemoteIPModule(module); err != nil {
			return err
		}
	}
	// Fail closed on quota/ownership/capacity; never mount, erase, enlarge or
	// repair an existing cache to make an application operation succeed.
	if err = s.prepareApacheBodyStorage(ctx, cfg); err != nil {
		return err
	}
	manifest := map[string]any{"id": "apache-waf", "version": core.ApacheWAFNativeBodyVersion, "settings": core.WAFSettings(cfg), "installed_at": installedAt, "updated_at": core.Now()}
	plan, err := txs.planApacheWAFTransaction(backups, updated, rules, manifest, false)
	if err != nil {
		return err
	}
	if err = txs.applyApacheWAFPlanned(ctx, plan, func(bounded context.Context) error {
		domain, e := apacheWAFConfigurationFilesMatchVersion(updated, cfg, module, paths[1], core.ApacheWAFNativeBodyVersion)
		if e != nil {
			return e
		}
		return apacheWAFWaitLoadedVersion(bounded, cfg, domain, core.ApacheWAFNativeBodyVersion)
	}, add); err != nil {
		return err
	}
	add("Apache2.4应用完整三文件事务与实际加载核验通过；请求体仅按明确站点策略启用，原程序、日志和失败历史保留")
	return nil
}
