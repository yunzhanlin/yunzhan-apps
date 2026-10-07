package executor

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

const wafBodyLoaderBegin = "# BEGIN PANEL NATIVE WAF LOADER\n"
const wafBodyLoaderEnd = "# END PANEL NATIVE WAF LOADER\n"
const wafBodySiteBegin = "  # BEGIN PANEL NATIVE WAF BODY\n"
const wafBodySiteEnd = "  # END PANEL NATIVE WAF BODY\n"

var wafBodyLoaderLine = regexp.MustCompile(`^load_module /opt/panel/app-modules/nginx-waf/engines/[0-9a-f]{32}/nginx/ngx_http_modsecurity_module\.so;\n$`)
var wafUnownedLoader = regexp.MustCompile(`(?m)^\s*load_module\s+[^;\n]*modsecurity[^;\n]*;`)

// Strip only an exact, uniquely owned marker block. A malformed or edited
// block is a conflict, not permission to remove arbitrary administrator text.
func stripWAFBodyBlocks(content, begin, end string, validate func(string) bool) (string, error) {
	if strings.Count(content, begin) != strings.Count(content, end) {
		return "", errors.New("请求体防护配置标记不完整，拒绝覆盖")
	}
	for strings.Contains(content, begin) {
		start := strings.Index(content, begin)
		tail := content[start+len(begin):]
		finish := strings.Index(tail, end)
		if finish < 0 || strings.Contains(tail[:finish], begin) || strings.Contains(content[:start], end) || !validate(tail[:finish]) {
			return "", errors.New("请求体防护受管块被外部修改，拒绝覆盖")
		}
		content = content[:start] + tail[finish+len(end):]
	}
	if strings.Contains(content, end) {
		return "", errors.New("请求体防护配置结束标记异常")
	}
	return content, nil
}

func renderWAFBodyLoader(content, engineJob string, enabled bool) (string, error) {
	if strings.Count(content, wafBodyLoaderBegin) > 1 {
		return "", errors.New("Nginx 原生引擎加载块重复")
	}
	base, err := stripWAFBodyBlocks(content, wafBodyLoaderBegin, wafBodyLoaderEnd, wafBodyLoaderLine.MatchString)
	if err != nil {
		return "", err
	}
	if enabled && wafUnownedLoader.MatchString(base) {
		return "", errors.New("Nginx 存在非云栈受管的 ModSecurity 模块，请先核对，未修改配置")
	}
	if !enabled {
		return base, nil
	}
	if !core.ValidID(engineJob) {
		return "", errors.New("原生引擎任务标识无效")
	}
	module := "/opt/panel/app-modules/nginx-waf/engines/" + engineJob + "/nginx/ngx_http_modsecurity_module.so"
	return wafBodyLoaderBegin + "load_module " + module + ";\n" + wafBodyLoaderEnd + base, nil
}

func wafBodySiteLines(id string) string {
	return "  modsecurity on;\n  modsecurity_rules_file /etc/panel/waf/body.d/" + id + ".conf;\n"
}

func renderWAFBodySite(content, id string, enabled bool) (string, error) {
	if !core.ValidID(id) || !strings.HasPrefix(content, "# managed by panel; site="+id) {
		return "", errors.New("请求体策略仅允许明确归属的受管网站")
	}
	base, err := stripWAFBodyBlocks(content, wafBodySiteBegin, wafBodySiteEnd, func(v string) bool { return v == wafBodySiteLines(id) })
	if err != nil {
		return "", err
	}
	if !enabled {
		return base, nil
	}
	first := strings.SplitN(base, "\n", 2)[0]
	if strings.Contains(first, "panel-waf-disabled") || strings.Contains(first, "; disabled") || !strings.Contains(base, "server {\n") {
		return "", errors.New("网站已停用或明确退出防火墙，不能启用请求体策略")
	}
	// These exact anchors are produced by the managed website renderer. A
	// custom configuration without them is refused rather than guessed/parsing
	// arbitrary Nginx syntax and inserting a directive into the wrong context.
	block := wafBodySiteBegin + wafBodySiteLines(id) + wafBodySiteEnd
	return strings.ReplaceAll(base, "server {\n", "server {\n"+block), nil
}

func wafBodyPolicyFile(v wafBodyPolicy, id, engineJob string) (string, error) {
	if !core.ValidID(id) || !core.ValidID(engineJob) {
		return "", errors.New("请求体站点或引擎标识无效")
	}
	source := filepath.Join("/opt/panel/app-modules/nginx-waf/engines", engineJob, "source")
	temporary := filepath.Join("/var/cache/panel-waf-body", id)
	rules, err := renderWAFBodyRules(v, source, temporary)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("# managed by panel; native-waf-site=%s; engine=%s\n", id, engineJob) + rules, nil
}
