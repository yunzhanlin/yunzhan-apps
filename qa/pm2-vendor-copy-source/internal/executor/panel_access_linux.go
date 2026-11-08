//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const panelAccessConfig = "/etc/panel/panel-access.conf"

func renderPanelAccess(v core.PanelAccess) (string, error) {
	if !core.ValidDomain(v.Domain) {
		return "", errors.New("面板域名无效")
	}
	if v.Port < 1024 || v.Port > 65535 || map[int]bool{19100: true, 19101: true, 19102: true, 22: true, 80: true, 443: true}[v.Port] {
		return "", errors.New("面板端口无效或为保留端口")
	}
	if v.HTTPSEnabled && !core.ValidID(v.CertificateID) {
		return "", errors.New("面板证书无效")
	}
	allows := []string{"127.0.0.1", "::1"}
	for _, raw := range v.AllowedCIDRs {
		_, network, e := net.ParseCIDR(raw)
		if e != nil {
			return "", errors.New("面板访问网段无效")
		}
		allows = append(allows, network.String())
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# managed by panel; revision=%d\n", v.Revision)
	if v.HTTPSEnabled {
		fmt.Fprintf(&b, "server {\n  listen 127.0.0.1:%d ssl;\n  listen [::1]:%d ssl;\n  server_name %s;\n", v.Port, v.Port, v.Domain)
		fmt.Fprintf(&b, "  ssl_certificate /etc/panel/certificates/%s/chain.pem;\n  ssl_certificate_key /etc/panel/certificates/%s/key.pem;\n", v.CertificateID, v.CertificateID)
		b.WriteString("  ssl_protocols TLSv1.2 TLSv1.3;\n  ssl_session_tickets off;\n  server_tokens off;\n")
		for _, value := range allows {
			fmt.Fprintf(&b, "  allow %s;\n", value)
		}
		b.WriteString("  deny all;\n  client_max_body_size 4g;\n  location / {\n    proxy_pass http://127.0.0.1:19100;\n    proxy_http_version 1.1;\n    proxy_set_header Host $http_host;\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Panel-Connection $connection;\n    proxy_read_timeout 100s;\n  }\n}\n")
	}
	if v.HTTPEnabled {
		entryLength := len(v.HTTPEntry)
		legacyEntry := entryLength >= 32 && entryLength <= 64
		if ip := net.ParseIP(v.HTTPIP); ip == nil || ip.To4() == nil || v.HTTPPort < 1024 || v.HTTPPort > 65535 || v.HTTPPort == v.Port || !((entryLength >= 8 && entryLength <= 10) || legacyEntry) {
			return "", errors.New("公网 HTTP 入口参数无效")
		}
		for _, r := range v.HTTPEntry {
			if legacyEntry && !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) || !legacyEntry && !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return "", errors.New("公网 HTTP 安全路径无效")
			}
		}
		fmt.Fprintf(&b, "server {\n  listen 0.0.0.0:%d;\n  server_name %s;\n  server_tokens off;\n  if ($host != %s) { return 404; }\n  add_header Referrer-Policy no-referrer always;\n  client_max_body_size 4g;\n", v.HTTPPort, v.HTTPIP, v.HTTPIP)
		fmt.Fprintf(&b, "  location = /%s {\n    access_log off;\n    return 302 /%s/;\n  }\n", v.HTTPEntry, v.HTTPEntry)
		fmt.Fprintf(&b, "  location ^~ /%s/ {\n    access_log off;\n    proxy_pass http://127.0.0.1:19100/;\n    proxy_http_version 1.1;\n    proxy_set_header Host $http_host;\n    proxy_set_header X-Forwarded-Proto http;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Panel-Connection public-http;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_read_timeout 100s;\n  }\n  location / { return 404; }\n}\n", v.HTTPEntry)
	}
	return b.String(), nil
}

func verifyPanelPublicHTTP(ctx context.Context, v core.PanelAccess) error {
	deadline := time.Now().Add(8 * time.Second)
	for {
		e := verifyPanelPublicHTTPOnce(ctx, v)
		if e == nil || time.Now().After(deadline) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func verifyPanelPublicHTTPOnce(ctx context.Context, v core.PanelAccess) error {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(v.HTTPPort)))
	}}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	defer client.CloseIdleConnections()
	request := func(path string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(v.HTTPIP, strconv.Itoa(v.HTTPPort))+path, nil)
		return client.Do(req)
	}
	for _, path := range []string{"/", "/api/health", "/assets/", "/wrong-entry/"} {
		denied, e := request(path)
		if e != nil {
			return e
		}
		denied.Body.Close()
		if denied.StatusCode != 404 {
			return fmt.Errorf("公网 HTTP 无入口路径 %s 应返回 404，实际 %d", path, denied.StatusCode)
		}
	}
	entry, e := request("/" + v.HTTPEntry + "/")
	if e != nil {
		return e
	}
	entry.Body.Close()
	if entry.StatusCode != 200 {
		return fmt.Errorf("公网 HTTP 安全入口返回 %d", entry.StatusCode)
	}
	health, e := request("/" + v.HTTPEntry + "/api/health")
	if e != nil {
		return e
	}
	defer health.Body.Close()
	if health.StatusCode != 200 {
		return fmt.Errorf("公网 HTTP 带安全路径的 API 返回 %d", health.StatusCode)
	}
	return nil
}

func verifyPanelHTTPS(ctx context.Context, v core.PanelAccess, cert core.Certificate) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cert.PEM)) {
		return errors.New("面板证书链不可建立信任")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: v.Domain, RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(v.Port)))
	}}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(4 * time.Second)
	var last error
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(v.Domain, strconv.Itoa(v.Port))+"/api/health", nil)
		response, e := client.Do(req)
		if e == nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
			response.Body.Close()
			if response.StatusCode == 200 && bytes.Contains(body, []byte(`"status":"ok"`)) {
				return nil
			}
			e = fmt.Errorf("面板 HTTPS 健康检查返回 HTTP %d", response.StatusCode)
		}
		last = e
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *Service) applyPanelAccess(ctx context.Context, v core.PanelAccess) (core.PanelAccessApplyResult, error) {
	result := core.PanelAccessApplyResult{Steps: []core.Step{}}
	add := func(message string) {
		result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
	}
	content, e := renderPanelAccess(v)
	if e != nil {
		return result, e
	}
	result.Config = content
	if e = ordinary(filepath.Dir(panelAccessConfig), true); e != nil {
		return result, e
	}
	old, readErr := os.ReadFile(panelAccessConfig)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	rollback := func() {
		if readErr == nil {
			_ = atomicWrite(panelAccessConfig, old, 0640)
		} else {
			_ = os.Remove(panelAccessConfig)
		}
		_, _ = s.Config.Run(context.Background(), "/usr/sbin/nginx", "-t")
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
	}
	if e = atomicWrite(panelAccessConfig, []byte(content), 0640); e != nil {
		return result, e
	}
	add("写入独立面板入口候选配置")
	if _, e = s.Config.Run(ctx, "/usr/sbin/nginx", "-t"); e != nil {
		rollback()
		return result, fmt.Errorf("Nginx 校验失败，已恢复原入口: %w", e)
	}
	add("Nginx 全量配置校验通过")
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); e != nil {
		rollback()
		return result, fmt.Errorf("Nginx 重载失败，已恢复原入口: %w", e)
	}
	if v.HTTPSEnabled {
		cert, e := LoadCertificate(v.CertificateID)
		if e != nil {
			rollback()
			return result, e
		}
		if e = cert.ValidateDomains(v.Domain, nil, time.Now()); e != nil {
			rollback()
			return result, e
		}
		if e = verifyPanelHTTPS(ctx, v, cert); e != nil {
			rollback()
			return result, fmt.Errorf("HTTPS 验证失败，已恢复原入口: %w", e)
		}
		add("使用目标域名、证书链和 TLS 1.2+ 验证管理 API")
	}
	if v.HTTPEnabled {
		if e = verifyPanelPublicHTTP(ctx, v); e != nil {
			rollback()
			return result, fmt.Errorf("公网 HTTP 验证失败，已恢复原入口: %w", e)
		}
		add("安全路径、门禁 Cookie 与 API 实际访问验证通过")
	}
	result.Status = "disabled"
	if v.HTTPSEnabled || v.HTTPEnabled {
		result.Status = "ready"
	}
	return result, nil
}

func (s *Service) panelAccessRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/panel-access/preview", func(w http.ResponseWriter, r *http.Request) {
		var in core.PanelAccessApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		content, e := renderPanelAccess(in.Config)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, core.PanelAccessApplyResult{Status: "preview", Config: content})
	})
	m.HandleFunc("POST /v1/panel-access/apply", func(w http.ResponseWriter, r *http.Request) {
		var in core.PanelAccessApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		result, e := s.applyPanelAccess(r.Context(), in.Config)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		respond(w, 200, result)
	})
}
