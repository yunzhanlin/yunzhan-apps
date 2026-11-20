package executor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"local/panel/internal/core"
)

const siteLoadBalancePrefix = "# panel-load-balance: "

func siteLoadBalanceMarker(domain string) string {
	if domain == "" {
		return ""
	}
	return siteLoadBalancePrefix + domain + "\n"
}

func disabledSiteConfig(site core.Site) string {
	return fmt.Sprintf("# managed by panel; site=%s; disabled\n", site.ID) + siteLoadBalanceMarker(site.Settings.LoadBalanceDomain)
}

func (s *Service) renderManagedSiteConfig(ctx context.Context, site core.Site, public string, enabled bool) (string, error) {
	upstream, err := s.siteLoadBalanceUpstream(ctx, site, enabled)
	if err != nil {
		return "", err
	}
	if !enabled && site.Settings.LoadBalanceDomain != "" {
		// Retain the desired binding and its ownership marker while stopped.
		return disabledSiteConfig(site), nil
	}
	return renderSiteConfigWithUpstream(site, public, upstream)
}

func (s *Service) siteBindingCandidate(in core.ApplyRequest, current, upstream string) (string, error) {
	previous := in.PreviousBindingSite
	site := in.Site
	if previous == nil || previous.ID != site.ID || previous.Domain != site.Domain || previous.Slug != site.Slug ||
		previous.PHPVersionID != site.PHPVersionID || previous.SettingsRevision != site.SettingsRevision ||
		previous.Status != site.Status || (site.Status != "running" && site.Status != "stopped") ||
		in.Enabled != (site.Status == "running") || previous.Settings.LoadBalanceDomain == site.Settings.LoadBalanceDomain ||
		in.PreserveNginx || in.PreviousSite != nil {
		return "", errors.New("网站分流变更的原始站点身份或配置状态无效")
	}
	public := filepath.Join(s.Config.SitesDir, site.ID, "public")
	if !in.Enabled {
		if current != disabledSiteConfig(*previous) {
			return "", errors.New("停用站点的实际配置与面板记录不同，已保留原文件")
		}
		return disabledSiteConfig(site), nil
	}
	oldUpstream, err := s.siteLoadBalancePreviousUpstream(previous.Settings.LoadBalanceDomain)
	if err != nil {
		return "", err
	}
	expected, err := renderSiteConfigWithUpstream(*previous, public, oldUpstream)
	if err != nil {
		return "", err
	}
	expected, err = s.preserveWAFBodySiteConfig(expected, site.ID)
	if err != nil {
		return "", err
	}
	if current != expected {
		return "", errors.New("站点含自定义配置或配置与面板记录不同，已保留原文件")
	}
	candidate, err := renderSiteConfigWithUpstream(site, public, upstream)
	if err != nil {
		return "", err
	}
	return s.preserveWAFBodySiteConfig(candidate, site.ID)
}
