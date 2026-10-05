package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

func renderSitePublicIngress(site core.Site, content string) string {
	if !site.Settings.PublicIngress {
		return content
	}
	content = strings.ReplaceAll(content, "  listen 127.0.0.1:19101;\n", "  listen 127.0.0.1:19101;\n  listen 0.0.0.0:80;\n  listen [::]:80;\n")
	content = strings.ReplaceAll(content, "  listen 127.0.0.1:19102 ssl;\n", "  listen 127.0.0.1:19102 ssl;\n  listen 0.0.0.0:443 ssl;\n  listen [::]:443 ssl;\n")
	return strings.ReplaceAll(content, "https://$host:19102$request_uri", "https://$host$request_uri")
}
func siteHTTPSRedirect(site core.Site, domain, path string) string {
	port := ":19102"
	if site.Settings.PublicIngress {
		port = ""
	}
	return "https://" + domain + port + path
}

// Check both address families independently. A surviving listener after disabling
// an ingress is a failed deployment, just like an unavailable enabled listener.
func verifySitePublicIngress(ctx context.Context, site core.Site) error {
	enabled := site.Settings.PublicIngress && site.Status != "stopped"
	addresses, err := publicIngressProbeAddresses(net.Listen)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		plain := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer plain.CloseIdleConnections()
		for _, domain := range append([]string{site.Domain}, site.Settings.Domains...) {
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(address, "80")+siteHealthPath(site), nil)
			req.Host = domain
			response, err := plain.Do(req)
			if err != nil {
				if enabled || !errors.Is(err, syscall.ECONNREFUSED) {
					return fmt.Errorf("标准 HTTP 入口 %s: %w", domain, err)
				}
			} else {
				body, er := io.ReadAll(io.LimitReader(response.Body, 512))
				response.Body.Close()
				if er != nil {
					return er
				}
				if enabled && (response.StatusCode != 200 || string(body) != siteHealthBody(site)) {
					return fmt.Errorf("标准 HTTP 入口 %s 的配置未生效", domain)
				}
				if !enabled && response.StatusCode != 404 {
					return fmt.Errorf("已关闭的标准入口 %s 仍返回 HTTP %d", domain, response.StatusCode)
				}
			}
			if !enabled || site.Settings.TLS == nil {
				dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, "443"))
				if err == nil {
					conn.Close()
					return fmt.Errorf("未启用标准 HTTPS 的网站 %s 仍接受 TLS 握手", domain)
				}
				continue
			}
			secure, err := siteHTTPSClient(site, domain)
			if err != nil {
				return err
			}
			req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort(address, "443")+siteHealthPath(site), nil)
			req.Host = domain
			response, err = secure.Do(req)
			if err != nil {
				secure.CloseIdleConnections()
				return err
			}
			body, er := io.ReadAll(io.LimitReader(response.Body, 512))
			response.Body.Close()
			secure.CloseIdleConnections()
			if er != nil {
				return er
			}
			if response.StatusCode != 200 || string(body) != siteHealthBody(site) {
				return fmt.Errorf("标准 HTTPS 入口 %s 的配置未生效", domain)
			}
			if site.Settings.TLS.Redirect {
				path := "/__panel_tls_redirect_check?panel=1&path=%2F"
				req, _ = http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(address, "80")+path, nil)
				req.Host = domain
				response, err = plain.Do(req)
				if err != nil {
					return err
				}
				response.Body.Close()
				if response.StatusCode != 301 || response.Header.Get("Location") != siteHTTPSRedirect(site, domain, path) {
					return fmt.Errorf("标准入口 %s 未保留 HTTPS 跳转路径", domain)
				}
			}
		}
	}
	return nil
}

// Some VPS images expose an IPv6 wildcard listener but do not configure ::1.
// Only probe an address family that the host can actually use for loopback.
func publicIngressProbeAddresses(listen func(string, string) (net.Listener, error)) ([]string, error) {
	addresses := []string{"127.0.0.1"}
	listener, err := listen("tcp6", "[::1]:0")
	if err == nil {
		_ = listener.Close()
		return append(addresses, "::1"), nil
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return addresses, nil
	}
	return nil, fmt.Errorf("IPv6 回环能力检查失败: %w", err)
}
