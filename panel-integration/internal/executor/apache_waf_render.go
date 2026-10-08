package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"regexp"
	"sort"
	"strings"
)

const apacheWAFInclude = "IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules.conf\n"

func apacheWAFBindings(source string) (map[string][]string, error) {
	if !strings.HasPrefix(source, "# managed by panel\n") {
		return nil, errors.New("Apache 配置不是云栈受管文件")
	}
	bindings := map[string][]string{}
	blocks := regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`).FindAllString(source, -1)
	for _, block := range blocks {
		id := regexp.MustCompile(`(?m)^\s*CustomLog /var/log/apache2/panel-([a-f0-9]{32})\.access\.log combined\s*$`).FindStringSubmatch(block)
		if len(id) != 2 {
			return nil, errors.New("无法识别 Apache 受管站点标识")
		}
		domains := []string{}
		for _, match := range regexp.MustCompile(`(?m)^\s*Server(?:Name|Alias)\s+([^\n]+)$`).FindAllStringSubmatch(block, -1) {
			for _, domain := range strings.Fields(match[1]) {
				if !core.ValidDomain(domain) {
					return nil, errors.New("Apache 站点域名无效")
				}
				domains = append(domains, domain)
			}
		}
		if len(domains) == 0 || len(bindings[id[1]]) != 0 {
			return nil, errors.New("Apache 站点域名缺失或标识重复")
		}
		bindings[id[1]] = domains
	}
	return bindings, nil
}

// Byte escapes are literal PCRE data: user text cannot introduce Apache syntax,
// directive substitutions, rewrite backreferences, spaces or raw expressions.
func apacheWAFLiteral(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		fmt.Fprintf(&out, "\\x%02x", value[i])
	}
	return out.String()
}
func apacheWAFDomainPattern(domains []string) string {
	items := make([]string, 0, len(domains))
	for _, domain := range domains {
		items = append(items, regexp.QuoteMeta(domain))
	}
	sort.Strings(items)
	return "^(?:" + strings.Join(items, "|") + ")$"
}
func apacheWAFProbe(cfg core.WAFConfig) string {
	b, _ := json.Marshal(cfg)
	return core.ApacheWAFVersion + ":" + core.Hash(string(b))
}

func renderApacheWAF(cfg core.WAFConfig, bindings map[string][]string) (string, error) {
	if err := core.ValidateApacheWAFTrustedProxy(cfg.TrustedProxy); err != nil {
		return "", err
	}
	for _, id := range core.WAFScopedSites(cfg) {
		if len(bindings[id]) == 0 {
			return "", errors.New("Apache 防护策略引用未运行或非 Apache 网站")
		}
	}
	var out strings.Builder
	out.WriteString("# managed by panel apache-waf " + core.ApacheWAFVersion + "; independently authored metadata rules\nRewriteEngine On\nRewriteOptions InheritDownBefore\n")
	// These directives are included only in managed Apache VirtualHosts. Never
	// emit RemoteIPHeader without an explicit list: Apache would trust all peers.
	if cfg.TrustedProxy != nil && cfg.TrustedProxy.Enabled {
		out.WriteString("# explicit trusted proxy peers; identity is independent of metadata blocking mode\n")
		for _, cidr := range cfg.TrustedProxy.TrustedCIDRs {
			fmt.Fprintf(&out, "RemoteIPInternalProxy %s\n", cidr)
		}
		out.WriteString("RemoteIPHeader X-Forwarded-For\n")
	}
	fmt.Fprintf(&out, "Header always set X-Panel-Apache-WAF \"%s\"\nRewriteRule ^ - [E=PANEL_AW_MODE:%s]\n", apacheWAFProbe(cfg), cfg.Policy.Mode)
	for _, site := range cfg.Policy.Sites {
		if cfg.Policy.Mode != "off" && site.Mode != "inherit" {
			fmt.Fprintf(&out, "RewriteCond %%{ENV:PANEL_AW_SITE} ^%s$\nRewriteRule ^ - [E=PANEL_AW_MODE:%s]\n", site.SiteID, site.Mode)
		}
	}
	begin := func(siteID string) {
		out.WriteString("RewriteCond %{ENV:PANEL_AW_MODE} !^off$\nRewriteCond %{ENV:PANEL_AW_ALLOW} !^1$\nRewriteCond %{ENV:PANEL_AW_REASON} ^$\n")
		if siteID != "" {
			fmt.Fprintf(&out, "RewriteCond %%{ENV:PANEL_AW_SITE} ^%s$\n", siteID)
		}
	}
	for _, kind := range []string{"ip_allow", "ip_deny", "ua_allow", "ua_deny", "url_allow", "url_deny"} {
		for _, entry := range cfg.Policy.Lists[kind] {
			begin(entry.SiteID)
			switch {
			case strings.HasPrefix(kind, "ip_"):
				fmt.Fprintf(&out, "RewriteCond expr \"-R '%s'\"\n", entry.Value)
			case strings.HasPrefix(kind, "ua_"):
				fmt.Fprintf(&out, "RewriteCond %%{HTTP_USER_AGENT} %s [NC]\n", apacheWAFLiteral(entry.Value))
			default:
				fmt.Fprintf(&out, "RewriteCond %%{REQUEST_URI} ^%s [NC]\n", apacheWAFLiteral(entry.Value))
			}
			if strings.HasSuffix(kind, "_allow") {
				out.WriteString("RewriteRule ^ - [E=PANEL_AW_ALLOW:1]\n")
			} else {
				fmt.Fprintf(&out, "RewriteRule ^ - [E=PANEL_AW_REASON:%s,E=PANEL_AW_ACTION:block]\n", strings.ReplaceAll(kind, "_", "-"))
			}
		}
	}
	patterns := core.WAFPatterns(cfg.Profile)
	for _, group := range core.WAFGroupNames {
		include, exclude := []string{}, []string{}
		for _, site := range cfg.Policy.Sites {
			if value, exists := site.Groups[group]; exists {
				if value {
					include = append(include, site.SiteID)
				} else {
					exclude = append(exclude, site.SiteID)
				}
			}
		}
		if !cfg.Policy.Groups[group] && len(include) == 0 {
			continue
		}
		begin("")
		if cfg.Policy.Groups[group] && len(exclude) != 0 {
			fmt.Fprintf(&out, "RewriteCond %%{ENV:PANEL_AW_SITE} !%s [NC]\n", apacheWAFDomainPattern(exclude))
		}
		if !cfg.Policy.Groups[group] {
			fmt.Fprintf(&out, "RewriteCond %%{ENV:PANEL_AW_SITE} %s [NC]\n", apacheWAFDomainPattern(include))
		}
		source, pattern := "%{REQUEST_URI}:%{QUERY_STRING}", patterns[group]
		if group == "method" {
			source, pattern = "%{REQUEST_METHOD}", "^(?:TRACE|TRACK)$"
		}
		if group == "scanner" {
			source = "%{HTTP_USER_AGENT}"
		}
		if group == "cookie" {
			source, pattern = "%{HTTP_COOKIE}", patterns["sql"]+"|"+patterns["xss"]+"|"+patterns["command"]+"|"+patterns["traversal"]
		}
		fmt.Fprintf(&out, "RewriteCond %s %s [NC]\nRewriteRule ^ - [E=PANEL_AW_REASON:%s,E=PANEL_AW_ACTION:block]\n", source, pattern, group)
	}
	for _, rule := range cfg.Policy.Rules {
		if !rule.Enabled {
			continue
		}
		begin(rule.SiteID)
		pattern := apacheWAFLiteral(rule.Value)
		if rule.Operator == "prefix" || rule.Operator == "exact" {
			pattern = "^" + pattern
		}
		if rule.Operator == "exact" {
			pattern += "$"
		}
		source := map[string]string{"uri": "%{REQUEST_URI}", "args": "%{QUERY_STRING}", "method": "%{REQUEST_METHOD}", "cookie": "%{HTTP_COOKIE}", "user_agent": "%{HTTP_USER_AGENT}"}[rule.Field]
		fmt.Fprintf(&out, "RewriteCond %s %s [NC]\nRewriteRule ^ - [E=PANEL_AW_REASON:custom-%s,E=PANEL_AW_ACTION:%s]\n", source, pattern, rule.ID, rule.Action)
	}
	out.WriteString("RewriteCond %{ENV:PANEL_AW_MODE} ^observe$\nRewriteCond %{ENV:PANEL_AW_REASON} !^$\nRewriteRule ^ - [E=PANEL_AW_ACTION:observe]\nRewriteCond %{ENV:PANEL_AW_MODE} ^block$\nRewriteCond %{ENV:PANEL_AW_ACTION} ^block$\nRewriteRule ^ - [F,L]\n")
	// No query string, cookie, user-agent or body is retained in the event log.
	out.WriteString("CustomLog /var/log/apache2/panel-waf.events.log \"{\\\"epoch\\\":%{sec}t,\\\"ip\\\":\\\"%a\\\",\\\"peer\\\":\\\"%{c}a\\\",\\\"site\\\":\\\"%v\\\",\\\"site_id\\\":\\\"%{PANEL_AW_SITE}e\\\",\\\"method\\\":\\\"%m\\\",\\\"path\\\":\\\"%U\\\",\\\"status\\\":%>s,\\\"reason\\\":\\\"%{PANEL_AW_REASON}e\\\",\\\"action\\\":\\\"%{PANEL_AW_ACTION}e\\\"}\" env=PANEL_AW_REASON\n")
	if out.Len() > 1<<20 {
		return "", errors.New("Apache 防护生成配置超过 1 MiB，未开始修改")
	}
	return out.String(), nil
}
