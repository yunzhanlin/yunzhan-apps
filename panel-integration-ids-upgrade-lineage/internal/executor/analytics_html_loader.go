package executor

import (
	"errors"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

const analyticsHTMLLoaderBegin = "# BEGIN PANEL ANALYTICS HTML LOADER\n"
const analyticsHTMLLoaderEnd = "# END PANEL ANALYTICS HTML LOADER\n"
const analyticsHTMLNativeRoot = "/opt/panel/app-modules/website-analytics/html-engines"

var analyticsHTMLLoaderLine = regexp.MustCompile(`^load_module /opt/panel/app-modules/website-analytics/html-engines/[0-9a-f]{32}/ngx_http_js_module\.so;\n$`)
var analyticsHTMLUnownedModule = regexp.MustCompile(`(?m)^\s*load_module\s+[^;\n]*ngx_http_js_module[^;\n]*;`)

func analyticsHTMLLoaderBlock(id string) string {
	return analyticsHTMLLoaderBegin + "load_module " + analyticsHTMLNativeRoot + "/" + id + "/ngx_http_js_module.so;\n" + analyticsHTMLLoaderEnd
}

// This scanner determines only the context at a uniquely marked block, not
// arbitrary nginx syntax. The selected real binary remains the syntax oracle.
// Quoted braces, escaped quotes and comments cannot authorize a nested loader.
func analyticsHTMLContextDepth(prefix string) (int, bool) {
	depth := 0
	var quote byte
	escaped, comment := false, false
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c == 0 {
			return 0, false
		}
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '#':
			comment = true
		case '\'', '"':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return 0, false
			}
		}
	}
	return depth, quote == 0 && !escaped && !comment
}

func analyticsHTMLGlobalContext(prefix string) bool {
	depth, valid := analyticsHTMLContextDepth(prefix)
	return valid && depth == 0
}

const analyticsHTMLHealthBegin = "  # BEGIN PANEL ANALYTICS HTML HEALTH\n"
const analyticsHTMLHealthEnd = "  # END PANEL ANALYTICS HTML HEALTH\n"
const analyticsHTMLHealthInclude = "  include /etc/panel/analytics-html/health.conf;\n"
const analyticsHTMLHealthSocket = "/run/panel-nginx/analytics-html-health.sock"

func renderAnalyticsHTMLHealthMount(content string, enabled bool) (string, error) {
	if len(content) > 1<<20 || strings.Count(content, analyticsHTMLHealthBegin) > 1 {
		return "", errors.New("HTML 健康检查挂载超限或重复")
	}
	if index := strings.Index(content, analyticsHTMLHealthBegin); index >= 0 {
		depth, valid := analyticsHTMLContextDepth(content[:index])
		if !valid || depth != 1 {
			return "", errors.New("HTML 健康检查挂载上下文异常")
		}
	}
	base, err := stripWAFBodyBlocks(content, analyticsHTMLHealthBegin, analyticsHTMLHealthEnd, func(body string) bool { return body == analyticsHTMLHealthInclude })
	if err != nil {
		return "", errors.New("HTML 健康检查挂载被外部修改")
	}
	if strings.Contains(base, "/etc/panel/analytics-html/health.conf") {
		return "", errors.New("存在非受管 HTML 健康检查挂载")
	}
	if !enabled {
		return base, nil
	}
	const anchor = "http {\n"
	index := strings.Index(base, anchor)
	if strings.Count(base, anchor) != 1 || !analyticsHTMLGlobalContext(base[:max(index, 0)]) || index < 0 {
		return "", errors.New("无法定位唯一受管全局 HTTP 块，未修改")
	}
	block := analyticsHTMLHealthBegin + analyticsHTMLHealthInclude + analyticsHTMLHealthEnd
	return base[:index+len(anchor)] + block + base[index+len(anchor):], nil
}

func analyticsHTMLHealthConfiguration(id string) (string, error) {
	if !core.ValidID(id) {
		return "", errors.New("HTML 健康检查引擎标识无效")
	}
	return "# managed by panel; analytics-html-engine=" + id + "; program=" + analyticsHTMLProgramSHA + "\nserver {\n  listen unix:" + analyticsHTMLHealthSocket + ";\n  server_name _;\n  access_log off;\n  js_engine qjs;\n  js_import analytics_html from " + analyticsHTMLProgramPath() + ";\n  set $panel_analytics_engine " + id + ";\n  set $panel_analytics_program_sha " + analyticsHTMLProgramSHA + ";\n  location = /health {\n    limit_except GET { deny all; }\n    js_content analytics_html.health;\n  }\n  location / { return 404; }\n}\n", nil
}

func renderAnalyticsHTMLLoader(content, id string, enabled bool) (string, error) {
	if len(content) > 1<<20 || strings.Count(content, analyticsHTMLLoaderBegin) > 1 {
		return "", errors.New("HTML 引擎主配置超过限额或加载块重复，未修改")
	}
	if index := strings.Index(content, analyticsHTMLLoaderBegin); index >= 0 && !analyticsHTMLGlobalContext(content[:index]) {
		return "", errors.New("HTML 引擎加载块不在主配置全局上下文，未修改")
	}
	base, err := stripWAFBodyBlocks(content, analyticsHTMLLoaderBegin, analyticsHTMLLoaderEnd, analyticsHTMLLoaderLine.MatchString)
	if err != nil {
		return "", errors.New("HTML 引擎加载标记被外部修改，未修改")
	}
	if enabled && analyticsHTMLUnownedModule.MatchString(base) {
		return "", errors.New("已存在非云栈受管的 Nginx JavaScript 模块，未修改")
	}
	if !enabled {
		return base, nil
	}
	if !core.ValidID(id) {
		return "", errors.New("HTML 引擎任务标识无效")
	}
	return analyticsHTMLLoaderBlock(id) + base, nil
}

func verifyAnalyticsHTMLLoader(content, id string) error {
	if !core.ValidID(id) {
		return errors.New("HTML 引擎标识无效")
	}
	expected, err := renderAnalyticsHTMLLoader(content, id, true)
	if err != nil {
		return err
	}
	// Other managed global modules may prepend their own blocks. Require the
	// exact unique loader at global scope, without demanding it be byte zero.
	block := analyticsHTMLLoaderBlock(id)
	if strings.Count(content, block) != 1 || strings.Count(expected, block) != 1 {
		return errors.New("当前主配置缺少唯一匹配的受管 HTML 引擎加载块")
	}
	return nil
}
