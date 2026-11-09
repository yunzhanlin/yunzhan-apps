package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func siteHealthPath(site core.Site) string { return "/__panel_health_" + site.ID }
func siteWAFInclude(site core.Site) string {
	if core.SiteWAFEnabled(site.Settings) {
		return "  set $panel_waf_site " + site.ID + ";\n  include /etc/panel/waf/server.d/*.conf;\n"
	}
	return ""
}
func siteHealthBody(site core.Site) string {
	b, _ := json.Marshal(struct {
		Settings core.SiteSettings
		PHP      string
	}{core.DefaultSiteSettings(site.Settings), site.PHPVersionID})
	return "panel:" + site.ID + ":" + core.Hash(string(b))
}
func websiteRoot(site core.Site, public string) (string, error) {
	settings := core.DefaultSiteSettings(site.Settings)
	if e := core.ValidateSiteSettings(settings, site.Domain, site.PHPVersionID); e != nil {
		return "", e
	}
	root := public
	if e := ordinary(root, true); e != nil {
		return "", e
	}
	if settings.DocumentRoot != "" {
		for _, part := range strings.Split(settings.DocumentRoot, "/") {
			root = filepath.Join(root, part)
			if e := ordinary(root, true); e != nil {
				return "", fmt.Errorf("文档目录必须已存在，且不能包含链接: %w", e)
			}
		}
	}
	return root, nil
}
func renderSiteConfig(site core.Site, public string) (string, error) {
	settings := core.DefaultSiteSettings(site.Settings)
	root, e := websiteRoot(site, public)
	if e != nil {
		return "", e
	}
	domains := append([]string{site.Domain}, settings.Domains...)
	indexFiles := []string{}
	for _, name := range settings.IndexFiles {
		lower := strings.ToLower(name)
		if site.PHPVersionID == "" && (strings.HasSuffix(lower, ".php") || strings.HasSuffix(lower, ".phtml") || strings.HasSuffix(lower, ".phar")) {
			continue
		}
		indexFiles = append(indexFiles, name)
	}
	if len(indexFiles) == 0 {
		indexFiles = []string{"index.html"}
	}
	var out strings.Builder
	wafMarker := ""
	if !core.SiteWAFEnabled(site.Settings) {
		wafMarker = "; panel-waf-disabled"
	}
	fmt.Fprintf(&out, "# managed by panel; site=%s%s\nserver {\n%s  listen 127.0.0.1:19101;\n  server_name %s;\n  root %s;\n  index %s;\n  disable_symlinks on;\n  access_log /var/log/nginx/panel-%s.access.log panel_site;\n  error_log /var/log/nginx/panel-%s.error.log warn;\n", site.ID, wafMarker, siteWAFInclude(site), strings.Join(domains, " "), strconv.Quote(root), strings.Join(indexFiles, " "), site.ID, site.ID)
	fmt.Fprintf(&out, "  location = %s { default_type text/plain; access_log off; return 200 %s; }\n", siteHealthPath(site), strconv.Quote(siteHealthBody(site)))
	fmt.Fprintf(&out, "  add_header X-Panel-Config %s always;\n", strconv.Quote(core.Hash(siteHealthBody(site))))
	out.WriteString(siteAnalyticsProxy(site))
	out.WriteString(siteAnalyticsHTMLInjection(site))
	out.WriteString(siteACMEConfig(site))
	if settings.WebServer == "apache" {
		out.WriteString("  location / {\n    proxy_pass http://127.0.0.1:19080;\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n  }\n}\n")
		return renderSitePublicIngress(site, renderSiteTLS(site, root, out.String())), nil
	}
	out.WriteString("  location ~ /\\. { deny all; }\n")
	out.WriteString(phpProbeConfig(site))
	switch settings.Mode {
	case "files":
		out.WriteString(phpConfig(site, filepath.Dir(public)))
		out.WriteString("  location / {\n")
		out.WriteString(siteAnalyticsHTMLFilters(site))
		switch settings.Rewrite {
		case "none":
			out.WriteString("    try_files $uri $uri/ =404;\n")
		case "spa":
			out.WriteString("    try_files $uri $uri/ /index.html;\n")
		case "wordpress":
			out.WriteString("    try_files $uri $uri/ /index.php?$args;\n")
		case "thinkphp":
			out.WriteString("    try_files $uri $uri/ /index.php?s=$uri&$args;\n")
		case "custom":
			for _, r := range settings.Rules {
				fmt.Fprintf(&out, "    rewrite %s %s %s;\n", strconv.Quote(r.Pattern), strconv.Quote(r.Replacement), r.Flag)
			}
			out.WriteString("    try_files $uri $uri/ =404;\n")
		}
		out.WriteString("  }\n")
	case "proxy":
		proxyHost := "$proxy_host"
		if settings.ProxyPreserveHost {
			proxyHost = "$host"
		}
		fmt.Fprintf(&out, "  location / {\n    proxy_pass %s;\n    proxy_http_version 1.1;\n    proxy_hide_header X-Panel-Config;\n    proxy_set_header Host %s;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $panel_connection_upgrade;\n    proxy_connect_timeout 5s;\n    proxy_read_timeout 60s;\n    proxy_ssl_server_name on;\n    proxy_ssl_verify on;\n    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;\n  }\n", strconv.Quote(settings.ProxyURL), proxyHost)
	case "redirect":
		target := settings.RedirectURL
		if settings.PreserveURI {
			target = strings.TrimSuffix(target, "/") + "$request_uri"
		}
		fmt.Fprintf(&out, "  location / { return %d %s; }\n", settings.RedirectCode, strconv.Quote(target))
	}
	out.WriteString("}\n")
	return renderSitePublicIngress(site, renderSiteTLS(site, root, out.String())), nil
}

func thinkPHPCompatibilityLocation(site core.Site, socket string) string {
	settings := core.DefaultSiteSettings(site.Settings)
	if site.PHPVersionID == "" || settings.Rewrite != "thinkphp" || socket == "" {
		return ""
	}
	// Do not use `try_files /index.php` here: Nginx rewrites $uri to
	// /index.php before evaluating FastCGI params, which destroys the legacy
	// PATH_INFO (/api.php/... or /admin.php/...). SCRIPT_FILENAME is fixed to
	// the existing front controller, and this location only matches those two
	// compatibility entry points.
	return fmt.Sprintf("  location ~ \"^/(?:api|admin)\\.php(?:/|$)\" {\n%s    fastcgi_hide_header X-Panel-Config;\n    include /etc/nginx/fastcgi_params;\n    fastcgi_param SCRIPT_FILENAME $document_root/index.php;\n    fastcgi_param SCRIPT_NAME /index.php;\n    fastcgi_param PATH_INFO $uri;\n    fastcgi_pass unix:%s;\n  }\n", siteAnalyticsHTMLFilters(site), socket)
}
func (s *Service) checkDomainOwners(site core.Site) error {
	domains := map[string]bool{site.Domain: true}
	for _, d := range site.Settings.Domains {
		domains[d] = true
	}
	entries, e := os.ReadDir(s.Config.ConfDir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() == site.ID+".conf" || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		filename := filepath.Join(s.Config.ConfDir, entry.Name())
		if e = ordinary(filename, false); e != nil {
			return e
		}
		f, e := os.Open(filename)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		if e != nil {
			return e
		}
		if len(b) > 65536 {
			return errors.New("现有站点配置超过允许大小，需要核对")
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "server_name ") {
				continue
			}
			for _, name := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(line, "server_name "), ";")) {
				if domains[name] {
					return fmt.Errorf("域名 %s 已出现在其他站点的实际 Nginx 配置中", name)
				}
			}
		}
	}
	return nil
}
func (s *Service) siteSettingsRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/preview", func(w http.ResponseWriter, r *http.Request) {
		var site core.Site
		if !readJSON(w, r, &site) {
			return
		}
		if !core.ValidID(site.ID) || !core.ValidDomain(site.Domain) || core.ValidateSite(site.Name, site.Slug) != nil {
			respond(w, 400, map[string]string{"error": "无效站点"})
			return
		}
		if e := s.checkDomainOwners(site); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if site.Settings.AnalyticsInjectHTML && site.Status == "running" && r.URL.Query().Get("analytics_baseline") != "1" {
			if err := s.requireAnalyticsHTMLReady(r.Context()); err != nil {
				respond(w, 409, map[string]string{"error": "HTML 自动接入引擎未通过当前 Nginx 的摘要与加载核验：" + err.Error() + "；未写入网站配置，可继续使用手工采集标签。"})
				return
			}
		}
		public := filepath.Join(s.Config.SitesDir, site.ID, "public")
		content, e := renderSiteConfig(site, public)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		config := filepath.Join(s.Config.ConfDir, site.ID+".conf")
		if e = ordinary(config, false); e != nil {
			respond(w, 409, map[string]string{"error": "站点配置尚未就绪"})
			return
		}
		previous, e := os.ReadFile(config)
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		if site.Status == "stopped" || strings.Contains(string(previous), "; disabled") {
			content = fmt.Sprintf("# managed by panel; site=%s; disabled\n", site.ID)
		} else {
			content, e = s.preserveWAFBodySiteConfig(content, site.ID)
			if e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		oldPHP, newPHP, e := s.phpSettingsPreview(site)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"current": string(previous), "candidate": content, "config_sha": core.Hash(string(previous)), "revision": site.SettingsRevision, "php_current": oldPHP, "php_candidate": newPHP})
	})
	m.HandleFunc("GET /v1/sites/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		kind := r.URL.Query().Get("kind")
		if kind == "" {
			kind = "access"
		}
		if !core.ValidID(id) || (kind != "access" && kind != "error") {
			respond(w, 400, map[string]string{"error": "日志类型或站点无效"})
			return
		}
		content, e := readSiteLog(id, kind)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"kind": kind, "content": content, "limit_bytes": 65536, "sampled_at": core.Now()})
	})
}

var logQuery = regexp.MustCompile(`\?[^\s"',]+`)

func redactSiteLog(content string) string { return logQuery.ReplaceAllString(content, "?[redacted]") }

func verifySiteIngress(ctx context.Context, site core.Site, legacy bool) error {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	domains := append([]string{site.Domain}, site.Settings.Domains...)
	for _, domain := range domains {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101"+siteHealthPath(site), nil)
		req.Host = domain
		response, e := client.Do(req)
		if e != nil {
			return e
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 256))
		response.Body.Close()
		if e != nil {
			return e
		}
		if site.Status == "stopped" {
			if response.StatusCode != 404 {
				return fmt.Errorf("停用站点 %s 仍有入口响应 HTTP %d", domain, response.StatusCode)
			}
			continue
		}
		if response.StatusCode == 200 && string(body) == siteHealthBody(site) {
			continue
		}
		if legacy && site.SettingsRevision == 0 && (response.StatusCode == 404 || (response.StatusCode == 200 && string(body) == "panel:"+site.ID)) {
			req, _ = http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/", nil)
			req.Host = domain
			response, e = client.Do(req)
			if e != nil {
				return e
			}
			response.Body.Close()
			if response.StatusCode == 200 {
				continue
			}
		}
		return fmt.Errorf("域名 %s 未通过当前站点入口检查", domain)
	}
	if e := verifySiteHTTPS(ctx, site); e != nil {
		return e
	}
	return verifySitePublicIngress(ctx, site)
}

func verifySiteHomepage(ctx context.Context, client *http.Client, site core.Site) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", siteURL(site, "/"), nil)
	req.Host = site.Domain
	response, e := client.Do(req)
	if e != nil {
		return 0, e
	}
	defer response.Body.Close()
	if response.Header.Get("X-Panel-Config") != core.Hash(siteHealthBody(site)) {
		return response.StatusCode, errors.New("首页响应尚未来自本次配置")
	}
	if response.StatusCode < 200 || response.StatusCode >= 500 {
		return response.StatusCode, fmt.Errorf("网站首页 HTTP %d", response.StatusCode)
	}
	if site.Settings.Mode == "redirect" && response.StatusCode != site.Settings.RedirectCode {
		return response.StatusCode, fmt.Errorf("重定向 HTTP %d，期望 %d", response.StatusCode, site.Settings.RedirectCode)
	}
	return response.StatusCode, nil
}
