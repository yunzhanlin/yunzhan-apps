package executor

import (
	"errors"
	"local/panel/internal/core"
	"regexp"
	"strings"
)

const wafCCSiteBegin = "  # BEGIN PANEL WAF CC MODE\n"
const wafCCSiteEnd = "  # END PANEL WAF CC MODE\n"

// Nginx accepts a literal dry-run setting, not a map variable. Keep this
// server-scoped and in the same recoverable website transaction as its policy.
func wafCCObservationVersion(version string) bool {
	return version == "2.3.0" || wafBodyRotationVersion(version)
}

func wafEffectiveMetadataMode(cfg core.WAFConfig, id string) string {
	mode := cfg.Policy.Mode
	for _, site := range cfg.Policy.Sites {
		if site.SiteID == id && mode != "off" && site.Mode != "inherit" && site.Mode != "" {
			return site.Mode
		}
	}
	return mode
}

func wafCCSiteLines(mode string) string {
	value := "off"
	if mode == "observe" {
		value = "on"
	}
	return "  limit_req_dry_run " + value + ";\n"
}

var wafUnownedRateDirective = regexp.MustCompile(`(?:^|[;{}\n])\s*limit_req(?:_[a-z_]+)?\s`)
var wafSiteIncludeDirective = regexp.MustCompile(`(?:^|[;{}\n])\s*include\s+([^;\n]+);`)

func renderWAFCCSite(content, id, mode string, enabled bool) (string, error) {
	if !core.ValidID(id) || !strings.HasPrefix(content, "# managed by panel; site="+id) {
		return "", errors.New("CC 模式仅允许明确归属的受管网站")
	}
	base, err := stripWAFBodyBlocks(content, wafCCSiteBegin, wafCCSiteEnd, func(v string) bool {
		return v == wafCCSiteLines("block") || v == wafCCSiteLines("observe")
	})
	if err != nil {
		return "", errors.New("CC 模式受管块不完整或被外部修改，拒绝覆盖")
	}
	first := strings.SplitN(base, "\n", 2)[0]
	if !enabled || strings.Contains(first, "panel-waf-disabled") || strings.Contains(first, "; disabled") || !strings.Contains(base, "server {\n") {
		return base, nil
	}
	if mode != "block" && mode != "observe" && mode != "off" {
		return "", errors.New("CC 网站模式无效")
	}
	// dry_run is shared by all inherited limit_req rules. Never turn an
	// administrator's independent limiter into observation mode incidentally.
	if mode == "observe" {
		if wafUnownedRateDirective.MatchString(base) {
			return "", errors.New("网站有独立限速指令，不能用 WAF 观察模式改变其阻断行为")
		}
		for _, match := range wafSiteIncludeDirective.FindAllStringSubmatch(base, -1) {
			if match[1] != "/etc/panel/waf/server.d/*.conf" && match[1] != "/etc/nginx/fastcgi_params" {
				return "", errors.New("网站包含外部配置，无法证明其限速不受观察模式影响，未修改")
			}
		}
	}
	include := "  include /etc/panel/waf/server.d/*.conf;\n"
	if strings.Count(base, include) != strings.Count(base, "server {\n") {
		return "", errors.New("CC 模式缺少每个受管 server 的唯一防火墙插入点")
	}
	block := wafCCSiteBegin + wafCCSiteLines(mode) + wafCCSiteEnd
	return strings.ReplaceAll(base, include, include+block), nil
}
