//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
)

// Stop, TLS and PHP changes must share the same cross-process lock as WAF
// deployment/recovery. Check before creating files or preparing a PHP worker.
func (s *Service) lockWAFSiteMutation() (func(), error) {
	_, pendingErr := os.Lstat(s.wafPendingPath())
	_, manifestErr := os.Lstat(s.softwareManifestPath("nginx-waf"))
	_, lbPendingErr := os.Lstat(s.loadBalancePendingPath())
	_, lbManifestErr := os.Lstat(filepath.Join(s.moduleDir("load-balance"), "installed.json"))
	html := s.analyticsHTMLTransactionService()
	_, htmlPendingErr := os.Lstat(html.wafPendingPath())
	_, htmlActiveErr := os.Lstat(s.systemPath("/etc/panel/analytics-html/active.json"))
	if errors.Is(pendingErr, os.ErrNotExist) && errors.Is(manifestErr, os.ErrNotExist) && errors.Is(lbPendingErr, os.ErrNotExist) && errors.Is(lbManifestErr, os.ErrNotExist) && errors.Is(htmlPendingErr, os.ErrNotExist) && errors.Is(htmlActiveErr, os.ErrNotExist) {
		return func() {}, nil
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, errors.New("防火墙存在未完成恢复事务，请先安全恢复，再修改或停用网站")
	}
	if _, err := os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, errors.New("负载均衡存在未完成恢复事务，请先安全恢复，再修改网站")
	}
	if _, err := os.Lstat(html.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, errors.New("HTML 引擎存在未完成恢复事务，请先安全恢复，再修改网站")
	}
	return func() { _ = lock.Close() }, nil
}

func (s *Service) wafSiteArchiveReference(id string) error {
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	for _, referenced := range core.WAFScopedSites(cfg) {
		if referenced == id {
			return errors.New("网站仍被防火墙策略、名单或请求体规则引用；请先移除关联策略再归档，未移动或删除网站文件")
		}
	}
	return nil
}

// Website edits regenerate Nginx configuration. Carry the independently saved
// body policy forward instead of silently dropping protection when changing a
// document root, PHP version, proxy, TLS certificate or domain.
func (s *Service) preserveWAFBodySiteConfig(content, id string) (string, error) {
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("防火墙存在未完成恢复事务，请先安全恢复，再修改网站")
	}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if errors.Is(err, os.ErrNotExist) {
		return content, nil
	}
	if err != nil {
		return "", err
	}
	// Explicit website opt-out pauses body inspection as well as metadata
	// rules. Keep its saved policy/rule file for a later deliberate re-enable.
	if strings.Contains(strings.SplitN(content, "\n", 2)[0], "panel-waf-disabled") {
		content, err = renderWAFBodySite(content, id, false)
		if err == nil && wafCCObservationVersion(manifest.Version) {
			content, err = renderWAFCCSite(content, id, "off", false)
		}
		return content, err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return "", err
	}
	if wafCCObservationVersion(manifest.Version) {
		mode := wafEffectiveMetadataMode(cfg, id)
		content, err = renderWAFCCSite(content, id, mode, true)
		if err != nil {
			return "", err
		}
		if mode == "observe" {
			if err := s.verifyWAFCCObservationIncludes(); err != nil {
				return "", err
			}
		}
	}
	if _, on := core.WAFEffectiveBodyPolicy(cfg, id); !on {
		return content, nil
	}
	if err := s.verifyWAFBodyEngine(cfg); err != nil {
		return "", err
	}
	policy, _ := core.WAFEffectiveBodyPolicy(cfg, id)
	expected, err := wafBodyPolicyFile(policy, id, cfg.Body.EngineJobID)
	if err != nil {
		return "", err
	}
	actual, err := os.ReadFile(s.systemPath("/etc/panel/waf/body.d/" + id + ".conf"))
	if err != nil || string(actual) != expected {
		return "", errors.New("网站请求体规则缺失或被修改，请先核对防火墙；未切换网站配置")
	}
	return renderWAFBodySite(content, id, true)
}
