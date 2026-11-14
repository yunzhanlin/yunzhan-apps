//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"local/panel/internal/core"
)

func (s *Service) siteLoadBalanceUpstream(ctx context.Context, site core.Site, enabled bool) (string, error) {
	domain := site.Settings.LoadBalanceDomain
	if domain == "" {
		return "", nil
	}
	if err := core.ValidateSiteSettings(site.Settings, site.Domain, site.PHPVersionID); err != nil {
		return "", err
	}
	if !enabled {
		// An already bound site can always be stopped, even if its upstream
		// is unavailable. New bindings on a stopped site must still resolve.
		raw, err := readPHPSwitchConfig(filepath.Join(s.Config.ConfDir, site.ID+".conf"))
		if err == nil && strings.Contains(string(raw), "\n"+siteLoadBalanceMarker(domain)) {
			return "", nil
		}
	}
	if err := s.siteLoadBalanceReady(ctx); err != nil {
		return "", err
	}
	entry, err := s.siteLoadBalanceEntry(domain)
	if err != nil {
		return "", err
	}
	entries, err := s.loadBalanceEntries()
	if err != nil {
		return "", err
	}
	if err := validateWebsiteBalanceNodes(entry, entries); err != nil {
		return "", err
	}
	if err := s.verifyLoadBalanceLive(ctx, entry); err != nil {
		return "", fmt.Errorf("无法核对负载均衡当前入口：%w", err)
	}
	return s.renderSiteLoadBalanceProxy(entry), nil
}

// An old origin may be down when the operator needs to detach it. Its
// authoritative configuration can still establish the previous vhost bytes.
func (s *Service) siteLoadBalancePreviousUpstream(domain string) (string, error) {
	if domain == "" {
		return "", nil
	}
	entry, err := s.siteLoadBalanceEntry(domain)
	if err != nil {
		return "", err
	}
	return s.renderSiteLoadBalanceProxy(entry), nil
}

func (s *Service) siteLoadBalanceEntry(domain string) (loadBalanceEntry, error) {
	entry, present, err := s.readLoadBalanceEntry(domain)
	if err != nil {
		return loadBalanceEntry{}, err
	}
	if !present || entry.Removed || entry.Format == 0 {
		return loadBalanceEntry{}, errors.New("选定入口不存在或缺少受管修订，请在负载均衡中保存后选择")
	}
	return entry, nil
}

func (s *Service) siteLoadBalanceReady(ctx context.Context) error {
	if _, err := os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
		return errors.New("负载均衡存在未完成事务，请先恢复")
	}
	if !s.moduleActionInstalled(ctx, "load-balance") {
		return errors.New("请先安装负载均衡并核对应用状态")
	}
	return nil
}

func (s *Service) renderSiteLoadBalanceProxy(entry loadBalanceEntry) string {
	protocol, host, tls := "http", "$host", ""
	if backend := entry.BackendTLS; backend != nil {
		protocol, host = "https", backend.ServerName
		tls = fmt.Sprintf("    proxy_ssl_server_name on;\n    proxy_ssl_name %s;\n    proxy_ssl_verify on;\n    proxy_ssl_verify_depth 4;\n    proxy_ssl_protocols TLSv1.2 TLSv1.3;\n    proxy_ssl_trusted_certificate %q;\n", host, s.loadBalanceCAPath(entry.Domain))
	}
	// The original ingress performs WAF, logging and certificate termination.
	// Use the same native upstream directly so ip_hash sees the effective
	// client address, including the site's configured WAF trusted proxy policy.
	return fmt.Sprintf(`  location / {
    proxy_pass %s://panel_lb_%s;
    proxy_http_version 1.1;
    proxy_hide_header X-Panel-Config;
    proxy_set_header Host %s;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header Forwarded "";
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $panel_connection_upgrade;
%s    proxy_connect_timeout 2s;
    proxy_read_timeout 30s;
    proxy_next_upstream error timeout http_502 http_503 http_504;
  }
`, protocol, loadBalanceID(entry.Domain), host, tls)
}

func validateWebsiteBalanceNodes(entry loadBalanceEntry, entries []loadBalanceEntry) error {
	// A browser-facing site must not feed another panel ingress or one of the
	// local balancers, whose paths and host selection can bounce traffic back.
	ports := map[int]bool{80: true, 443: true, 19080: true, 19100: true, 19101: true, 19102: true, entry.Port: true}
	for _, v := range entries {
		ports[v.Port] = true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return errors.New("无法核对本机地址，未启用网站分流")
	}
	local := map[netip.Addr]bool{}
	for _, addr := range addresses {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	for _, node := range entry.Nodes {
		ip, port, err := loadBalanceNodeAddress(node.Address)
		if err != nil {
			return err
		}
		checkPort := port
		if entry.HealthCheck != nil && entry.HealthCheck.CheckPort != 0 {
			checkPort = entry.HealthCheck.CheckPort
		}
		if (ip.IsLoopback() || local[ip]) && (ports[port] || ports[checkPort]) {
			return errors.New("网站分流节点不可指向本机面板、网站入口或其他负载均衡入口")
		}
	}
	return nil
}

func (s *Service) siteLoadBalanceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/sites/load-balancers", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := core.SiteLoadBalanceChoices{Entries: []core.SiteLoadBalanceChoice{}}
		if _, err := s.moduleInstalledRecord("load-balance"); errors.Is(err, os.ErrNotExist) {
			respond(w, 200, out)
			return
		}
		lock, err := s.lockWAFObservation()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		defer lock.Close()
		if err := s.siteLoadBalanceReady(r.Context()); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		entries, err := s.loadBalanceEntries()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		out.Installed = true
		for _, entry := range entries {
			if entry.Format > 0 && validateWebsiteBalanceNodes(entry, entries) == nil {
				out.Entries = append(out.Entries, core.SiteLoadBalanceChoice{Domain: entry.Domain, TLS: entry.BackendTLS != nil, Sticky: entry.Sticky})
			}
		}
		respond(w, 200, out)
	})
}

// HTTP pools listen on their own loopback port. An exact managed pool
// configuration may share a name with a separate website virtual host.
func (s *Service) siteLoadBalanceSeparateListener(path, domain string) bool {
	if !core.ValidDomain(domain) {
		return false
	}
	config, _ := s.loadBalancePaths(domain)
	if path != config {
		return false
	}
	entry, present, err := s.readLoadBalanceEntry(domain)
	return err == nil && present && !entry.Removed
}

// Active and stopped sites both retain their reference in the first two lines.
// Inspect actual executor configuration under the same write lock used by
// Apply; an interrupted database receipt cannot silently free an active pool.
func (s *Service) siteLoadBalanceReferences() (map[string]bool, error) {
	configs, err := os.ReadDir(s.Config.ConfDir)
	if err != nil {
		return nil, err
	}
	references := map[string]bool{}
	for _, config := range configs {
		id, ok := strings.CutSuffix(config.Name(), ".conf")
		if !ok || !core.ValidID(id) {
			continue
		}
		raw, err := readPHPSwitchConfig(filepath.Join(s.Config.ConfDir, config.Name()))
		if err != nil {
			return nil, fmt.Errorf("无法核对站点 %s 的入口引用：%w", id, err)
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			domain, ok := strings.CutPrefix(line, siteLoadBalancePrefix)
			if !ok {
				continue
			}
			if !core.ValidDomain(domain) {
				return nil, errors.New("网站负载均衡引用标识异常，请核对配置")
			}
			references[domain] = true
		}
	}
	return references, nil
}

func (s *Service) checkLoadBalanceWebsiteChange(old, next loadBalanceEntry, entries []loadBalanceEntry) error {
	refs, err := s.siteLoadBalanceReferences()
	if err != nil {
		return err
	}
	if refs[next.Domain] {
		if next.Removed {
			return errors.New("入口仍有网站绑定，请先解除绑定再移除")
		}
		backendName := func(tls *core.LoadBalanceBackendTLS) string {
			if tls != nil {
				return tls.ServerName
			}
			return ""
		}
		if backendName(old.BackendTLS) != backendName(next.BackendTLS) {
			return errors.New("改变转发协议或 HTTPS 后端名称前，请先解除网站绑定")
		}
		if err := validateWebsiteBalanceNodes(next, entries); err != nil {
			return err
		}
	}
	// A newly occupied loopback port must not convert a bound site's existing
	// local backend into a second balancer and enable an accidental cycle.
	if !next.Removed && next.Port != old.Port {
		for _, entry := range entries {
			if entry.Domain != next.Domain && refs[entry.Domain] {
				if err := validateWebsiteBalanceNodes(entry, []loadBalanceEntry{next}); err != nil {
					return fmt.Errorf("新入口端口与已绑定网站的上游冲突：%w", err)
				}
			}
		}
	}
	return nil
}
