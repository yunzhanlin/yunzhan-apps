//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

// Activation checks are NOT a download/retry/repair. No caller path, key,
// readiness flag or network client can authorize a geo include. Published
// data is immutable, so read-only verification never takes the cache writer
// lock while the ordinary WAF transaction already owns its configuration lock.
func (s *Service) verifyWAFCountryPolicyCache(ctx context.Context, cfg core.WAFConfig) error {
	if cfg.Country == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || core.WAFVersion != core.WAFCountryDataVersion || os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" {
		return errors.New("国家策略尚无完整固定Root处理器，未采用数据或修改配置")
	}
	_, active, err := renderWAFCountryMaps(cfg.Country, cfg.Policy.Mode)
	if err != nil {
		return err
	}
	if !active {
		return nil // Disabling never downloads, repairs or deletes public data.
	}
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	_, instance, err := s.readWAFCountryInstance()
	if err != nil {
		return err
	}
	if err := s.wafCountryInstanceGuard(instance); err != nil {
		return errors.New("请先正常签名安装完整防火墙，再启用当前实例的国家策略")
	}
	store := countryCacheStore{base: countryCacheRoot, trust: appcatalog.Default(), now: time.Now}
	base, err := store.open(false)
	if err != nil {
		return err
	}
	defer base.Close()
	entry, authority, err := store.loadAuthority(ctx, base, cfg.Country.Data.Dataset)
	if err != nil {
		return err
	}
	data := cfg.Country.Data
	if !entry.Published || entry.DataManifestSHA != data.DataManifestSHA || entry.Release != data.Release || entry.Revision != data.Revision || !reflect.DeepEqual(entry.Countries, data.Countries) {
		return errors.New("国家策略与完整独立验签的数据集不同，没有应用任何配置")
	}
	if authority.StaleForNewPolicy(time.Now()) {
		return errors.New("地域数据已超过90天或时钟异常，请准备新数据后再启用策略；当前运行配置保持不变")
	}
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	return s.wafCountryInstanceGuard(instance)
}
