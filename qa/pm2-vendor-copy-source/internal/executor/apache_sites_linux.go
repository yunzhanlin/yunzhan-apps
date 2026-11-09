//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func apacheRelease() (runtimecatalog.Release, error) {
	r, ok := runtimecatalog.Find("apache-2.4.68")
	if !ok {
		return runtimecatalog.Release{}, errors.New("Apache 运行时目录缺少 2.4.68")
	}
	if e := ordinary(r.CLI(), false); e != nil {
		return runtimecatalog.Release{}, errors.New("请先安装 Apache 2.4.68")
	}
	return r, nil
}

func renderApacheSites(sites []core.Site, sitesDir string) (string, int, error) {
	r, e := apacheRelease()
	if e != nil {
		for _, site := range sites {
			if site.Status != "stopped" && core.DefaultSiteSettings(site.Settings).WebServer == "apache" {
				return "", 0, e
			}
		}
		return "", 0, nil
	}
	modules := []string{"mpm_event", "authz_core", "authz_host", "unixd", "log_config", "mime", "dir", "env", "setenvif", "headers", "rewrite", "proxy", "proxy_fcgi"}
	if ordinary(filepath.Join(r.Prefix(), "modules/mod_remoteip.so"), false) == nil {
		modules = append(modules, "remoteip")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# managed by panel\nServerRoot %s\nPidFile /run/panel-apache.pid\nListen 127.0.0.1:19080\nServerName 127.0.0.1\nUser www-data\nGroup www-data\nErrorLog /var/log/apache2/panel-error.log\nLogLevel warn\nLogFormat \"%%h %%l %%u %%t \\\"%%r\\\" %%>s %%b\" combined\n", strconv.Quote(r.Prefix()))
	for _, module := range modules {
		name := module + "_module"
		if module == "mpm_event" {
			name = "mpm_event_module"
		}
		fmt.Fprintf(&out, "LoadModule %s %s\n", name, strconv.Quote(filepath.Join(r.Prefix(), "modules/mod_"+module+".so")))
	}
	out.WriteString("TypesConfig /etc/mime.types\nDirectoryIndex index.php index.html\n<Directory />\n  AllowOverride None\n  Require all denied\n</Directory>\n")
	count := 0
	for _, site := range sites {
		settings := core.DefaultSiteSettings(site.Settings)
		if site.Status == "stopped" || settings.WebServer != "apache" {
			continue
		}
		if e = core.ValidateSiteSettings(settings, site.Domain, site.PHPVersionID); e != nil {
			return "", 0, e
		}
		public := filepath.Join(sitesDir, site.ID, "public")
		root, er := websiteRoot(site, public)
		if er != nil {
			return "", 0, er
		}
		domains := append([]string{site.Domain}, settings.Domains...)
		fmt.Fprintf(&out, "<VirtualHost 127.0.0.1:19080>\n  ServerName %s\n", site.Domain)
		fmt.Fprintf(&out, "  SetEnvIfExpr \"true\" PANEL_AW_SITE=%s\n", site.ID)
		out.WriteString("  " + apacheWAFInclude)
		if len(domains) > 1 {
			fmt.Fprintf(&out, "  ServerAlias %s\n", strings.Join(domains[1:], " "))
		}
		fmt.Fprintf(&out, "  DocumentRoot %s\n  ErrorLog /var/log/apache2/panel-%s.error.log\n  CustomLog /var/log/apache2/panel-%s.access.log combined\n", strconv.Quote(root), site.ID, site.ID)
		if settings.Rewrite != "none" {
			// Directory-context rewriting requires a symlink-following option
			// and otherwise rejects unrelated PHP probes with AH00670. Keep
			// the no-follow policy and rewrite URLs in this managed vhost.
			out.WriteString("  RewriteEngine On\n")
			switch settings.Rewrite {
			case "spa":
				out.WriteString("  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-f\n  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-d\n  RewriteRule ^/ /index.html [PT,L,NS]\n")
			case "wordpress":
				out.WriteString("  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-f\n  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-d\n  RewriteRule ^/ /index.php [PT,L,QSA,NS]\n")
			case "thinkphp":
				out.WriteString("  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-f\n  RewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-d\n  RewriteRule ^/.*$ /index.php?s=$0 [PT,L,QSA,NS]\n")
			case "custom":
				for _, rule := range settings.Rules {
					// Preserve slashless Apache patterns and the requested ^
					// anchor. PT retains URL mapping rather than filesystem-path
					// inference for a substituted value.
					pattern := "^/" + strings.TrimPrefix(strings.TrimPrefix(rule.Pattern, "^/"), "^")
					replacement, flags := apacheRewriteReplacement(rule.Replacement)
					fmt.Fprintf(&out, "  RewriteRule %s %s [%s]\n", pattern, replacement, flags)
				}
			}
		}
		fmt.Fprintf(&out, "  <Directory %s>\n    Options -Indexes -FollowSymLinks\n    AllowOverride None\n    Require all granted\n  </Directory>\n  <FilesMatch \"^\\.\">\n    Require all denied\n  </FilesMatch>\n", strconv.Quote(root))
		if site.PHPVersionID != "" {
			fmt.Fprintf(&out, "  <FilesMatch \"\\.php$\">\n    SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n  </FilesMatch>\n", poolSocket(site))
		}
		out.WriteString("</VirtualHost>\n")
		count++
	}
	return out.String(), count, nil
}

// Core admits only $1-$9 and these four URL variables. Expand the fixed
// variables and retain backreferences; never pass arbitrary expressions or
// append the original query twice when it is explicitly substituted.
func apacheRewriteReplacement(value string) (string, string) {
	hasQuery := strings.Contains(value, "$args") || strings.Contains(value, "$query_string")
	flags := "PT,L"
	if strings.Contains(value, "$is_args") && !hasQuery {
		flags += ",QSA"
	}
	value = strings.NewReplacer("$query_string", "%{QUERY_STRING}", "$is_args", "?", "$args", "%{QUERY_STRING}", "$uri", "%{REQUEST_URI}").Replace(value)
	return value, flags
}

func (s *Service) applyApacheSites(ctx context.Context, sites []core.Site, add func(string)) (func() error, error) {
	content, count, e := renderApacheSites(sites, s.Config.SitesDir)
	if e != nil {
		return nil, e
	}
	if rollback, handled, err := s.applyApacheNativeBodySites(ctx, content, count, add); handled {
		return rollback, err
	}
	if rollback, handled, err := s.applyApacheWAFMetadataSites(ctx, content, count, add); handled {
		return rollback, err
	}
	old, readErr := os.ReadFile(s.Config.ApacheSiteConfig)
	hadOld := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	wasActive := false
	if output, er := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache"); er == nil && strings.TrimSpace(output) == "active" {
		wasActive = true
	}
	wasEnabled := false
	if output, er := s.Config.Run(ctx, "/usr/bin/systemctl", "is-enabled", "panel-apache"); er == nil && strings.TrimSpace(output) == "enabled" {
		wasEnabled = true
	}
	rollback := func() error {
		var restoreErr error
		if hadOld {
			restoreErr = errors.Join(restoreErr, atomicWrite(s.Config.ApacheSiteConfig, old, 0644))
		} else {
			if er := os.Remove(s.Config.ApacheSiteConfig); er != nil && !errors.Is(er, os.ErrNotExist) {
				restoreErr = errors.Join(restoreErr, er)
			}
		}
		if wasEnabled {
			_, e = s.Config.Run(context.Background(), "/usr/bin/systemctl", "enable", "panel-apache")
		} else {
			_, e = s.Config.Run(context.Background(), "/usr/bin/systemctl", "disable", "panel-apache")
		}
		restoreErr = errors.Join(restoreErr, e)
		if wasActive {
			_, e = s.Config.Run(context.Background(), "/usr/bin/systemctl", "restart", "panel-apache")
		} else {
			_, e = s.Config.Run(context.Background(), "/usr/bin/systemctl", "stop", "panel-apache")
		}
		return errors.Join(restoreErr, e)
	}
	if count == 0 {
		if wasActive || wasEnabled {
			if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", "panel-apache"); e != nil {
				return nil, e
			}
			add("当前没有 Apache 网站，停止共享 Apache 服务并取消开机启动")
		}
		return rollback, nil
	}
	if e = os.MkdirAll(filepath.Dir(s.Config.ApacheSiteConfig), 0755); e != nil {
		return nil, e
	}
	if e = os.MkdirAll("/var/log/apache2", 0755); e != nil {
		return nil, e
	}
	if e = atomicWrite(s.Config.ApacheSiteConfig, []byte(content), 0644); e != nil {
		return nil, e
	}
	r, _ := apacheRelease()
	if _, e = s.Config.Run(ctx, r.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); e != nil {
		if restoreErr := rollback(); restoreErr != nil {
			return nil, fmt.Errorf("Apache 配置校验失败且恢复失败: %v / %w", restoreErr, e)
		}
		return nil, fmt.Errorf("Apache 配置校验失败: %w", e)
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "panel-apache"); e != nil {
		if restoreErr := rollback(); restoreErr != nil {
			return nil, fmt.Errorf("Apache 服务开机启动配置失败且恢复失败: %v / %w", restoreErr, e)
		}
		return nil, fmt.Errorf("Apache 服务开机启动配置失败: %w", e)
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-apache"); e != nil {
		if restoreErr := rollback(); restoreErr != nil {
			return nil, fmt.Errorf("Apache 服务启动失败且恢复失败: %v / %w", restoreErr, e)
		}
		return nil, fmt.Errorf("Apache 服务启动失败: %w", e)
	}
	add(fmt.Sprintf("生成并启动 Apache 2.4.68，共承载 %d 个网站", count))
	return rollback, nil
}
