//go:build !linux

package executor

import (
	"context"
	"errors"
	"net/http"

	"local/panel/internal/core"
)

func (s *Service) siteLoadBalanceUpstream(_ context.Context, site core.Site, _ bool) (string, error) {
	if site.Settings.LoadBalanceDomain != "" {
		return "", errors.New("网站负载均衡绑定需要 Linux 执行器")
	}
	return "", nil
}

func (s *Service) siteLoadBalanceRoutes(m *http.ServeMux) {}

func (s *Service) siteLoadBalanceSeparateListener(_, _ string) bool { return false }

func (s *Service) siteLoadBalancePreviousUpstream(domain string) (string, error) {
	return s.siteLoadBalanceUpstream(context.Background(), core.Site{Settings: core.SiteSettings{LoadBalanceDomain: domain}}, true)
}
