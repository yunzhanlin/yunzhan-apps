//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/core"
)

// Current hard-quota and ownership facts only. No mkdir, mount, repair or log
// creation from status/preview. Capacity is rechecked before explicit activation.
func verifyApacheNativeBodyStorage(cfg core.WAFConfig) error {
	if !apacheBodyActive(cfg) {
		return nil
	}
	if _, err := verifyApacheBodyCacheQuota(); err != nil {
		return err
	}
	uid, gid, err := apacheBodyWorkerAccount()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(apacheBodyTemporary)
	if err != nil || len(entries) > 64 {
		return errors.New("Apache 原生缓存完整库存不可核对")
	}
	present := map[string]bool{}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) {
			return errors.New("Apache 缓存含未知目录，未接管或删除")
		}
		st, e := os.Lstat(filepath.Join(apacheBodyTemporary, entry.Name()))
		if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("Apache 缓存目录权限或类型异常")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) {
			return errors.New("Apache 缓存目录账户异常")
		}
		present[entry.Name()] = true
	}
	for _, site := range cfg.Body.Sites {
		if _, active := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); active && !present[site.SiteID] {
			return errors.New("Apache 原生站点缓存缺失，状态读取不自动修复")
		}
	}
	f, err := openApacheBodyMetadataLog()
	if err != nil {
		return err
	}
	return f.Close()
}

func (s *Service) apacheNativePreview(ctx context.Context, raw map[string]any) (map[string]any, error) {
	current, err := s.apacheNativeCurrent()
	if err != nil {
		return nil, err
	}
	if current["version"] != core.ApacheWAFNativeBodyVersion {
		return nil, errors.New("预览不授予原生版本，先签名升级Apache应用")
	}
	previous, err := core.DecodeApacheWAFNativeBodyConfig(current["settings"].(map[string]any))
	if err != nil {
		return nil, err
	}
	cfg, err := s.apacheNativeSettings(raw, false, false)
	if err != nil {
		return nil, err
	}
	source, _, err := s.apacheWAFSource()
	if err != nil {
		return nil, err
	}
	release, err := apacheRelease()
	if err != nil {
		return nil, err
	}
	module := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	if _, err = apacheWAFConfigurationFilesMatchVersion(source, previous, module, filepath.Join(s.moduleDir("apache-waf"), "rules.conf"), core.ApacheWAFNativeBodyVersion); err != nil {
		return nil, err
	}
	next := cfg
	next.Policy.Revision++
	prepared, rules, err := apacheNativeCandidate(source, previous, next, module)
	if err != nil {
		return nil, err
	}
	if err = s.verifyApacheBodyTransition(ctx, previous, cfg); err != nil {
		return nil, err
	}
	if cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled {
		if err = verifyApacheWAFRemoteIPModule(module); err != nil {
			return nil, err
		}
	}
	if apacheBodyActive(cfg) {
		capacity, e := verifyApacheBodyCacheQuota()
		if e != nil {
			return nil, e
		}
		if capacity.AvailableBytes < apacheBodyCacheReserveBytes || capacity.AvailableNodes < 128 {
			return nil, errors.New("Apache 请求体缓存可用预算不足；预览未清理或扩大配额")
		}
		if e = verifyApacheBodyMetadataDirectory(); e != nil {
			return nil, e
		}
	}
	return map[string]any{"settings": cfg, "http_config": prepared, "server_config": rules, "read_only": true, "body_activation_explicit": true, "implementation_version": core.ApacheWAFNativeBodyVersion, "planned_revision": next.Policy.Revision}, nil
}
