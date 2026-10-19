package executor

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

const apacheBodyGlobalBegin = "# BEGIN PANEL APACHE NATIVE BODY\n"
const apacheBodyGlobalEnd = "# END PANEL APACHE NATIVE BODY\n"
const apacheBodySiteBegin = "  # BEGIN PANEL APACHE NATIVE BODY SITE\n"
const apacheBodySiteEnd = "  # END PANEL APACHE NATIVE BODY SITE\n"
const apacheBodyTemporary = "/var/cache/panel-apache-body"

var apacheBodyHosts = regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`)
var apacheBodySiteIdentity = regexp.MustCompile(`(?m)^\s*CustomLog /var/log/apache2/panel-([a-f0-9]{32})\.access\.log combined\s*$`)
var apacheBodyExternalDirective = regexp.MustCompile(`(?mi)^\s*(?:Sec[A-Za-z0-9_]*|LoadModule\s+security2_module|LoadModule\s+\S+\s+[^\n]*mod_security2\.so["']?)(?:\s|$)`)

func apacheBodyActive(cfg core.WAFConfig) bool {
	if cfg.Body == nil {
		return false
	}
	for _, site := range cfg.Body.Sites {
		if _, active := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); active {
			return true
		}
	}
	return false
}

// No untrusted path or directive enters these blocks. The selected program is
// separately rehashed by the privileged activation planner before any write.
func apacheBodyGlobalBlock(cfg core.WAFConfig, base string) (string, error) {
	if !apacheBodyActive(cfg) {
		return "", nil
	}
	if cfg.Body == nil || !core.ValidID(cfg.Body.EngineJobID) {
		return "", errors.New("Apache 请求体引擎任务身份缺失")
	}
	prefix := filepath.Join(apacheBodyEngines, cfg.Body.EngineJobID)
	global, err := renderApacheBodyGlobalRules(filepath.Join(prefix, "source"))
	if err != nil {
		return "", err
	}
	unique := "LoadModule unique_id_module /opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so\n"
	loads := regexp.MustCompile(`(?mi)^\s*LoadModule\s+unique_id_module\s+([^\n]+)$`).FindAllStringSubmatch(base, -1)
	if len(loads) > 1 {
		return "", errors.New("Apache unique_id 模块重复，拒绝猜测修复")
	}
	if len(loads) == 1 {
		if strings.TrimSpace(loads[0][1]) != "/opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so" && strings.TrimSpace(loads[0][1]) != `"/opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so"` {
			return "", errors.New("Apache unique_id 模块不是受管固定程序")
		}
		unique = ""
	}
	return apacheBodyGlobalBegin + unique + "LoadModule security2_module " + filepath.Join(prefix, "apache/mod_security2.so") + "\nSecRuleEngine Off\n" + global + apacheBodyGlobalEnd, nil
}

func apacheBodySiteBlock(cfg core.WAFConfig, id string) (string, error) {
	p, active := core.WAFEffectiveBodyPolicy(cfg, id)
	if !active {
		return "", nil
	}
	if cfg.Body == nil || !core.ValidID(cfg.Body.EngineJobID) {
		return "", errors.New("Apache 请求体引擎任务身份缺失")
	}
	prefix := filepath.Join(apacheBodyEngines, cfg.Body.EngineJobID)
	rules, err := renderApacheBodySiteRules(p, filepath.Join(prefix, "source"), filepath.Join(apacheBodyTemporary, id), id)
	if err != nil {
		return "", err
	}
	return apacheBodySiteBegin + rules + apacheBodySiteEnd, nil
}

// Strip only an exact previously generated section. Foreign edits, missing
// markers, duplicate sections and stale manifest-policy mismatches fail closed.
func apacheBodyStripBlock(source, begin, end, expected string) (string, error) {
	starts, ends := strings.Count(source, begin), strings.Count(source, end)
	if expected == "" {
		if starts != 0 || ends != 0 {
			return "", errors.New("Apache 出现未声明的请求体受管区块")
		}
		return source, nil
	}
	if starts != 1 || ends != 1 || strings.Count(source, expected) != 1 {
		return "", errors.New("Apache 请求体区块被外部修改、缺失或重复，未覆盖配置")
	}
	return strings.Replace(source, expected, "", 1), nil
}

// Exactly three existing journal files are sufficient: the complete native
// per-site body rules live in the main Apache configuration, not extra mutable
// rule files outside recovery's allowlist. Removing a policy removes its own
// complete section; no other site directive, comment, rewrite or PHP handler is
// changed. This pure renderer never claims a sealed program or reload success.
func transitionApacheBodySource(source string, previous, next core.WAFConfig) (string, error) {
	if len(source) > 2<<20 {
		return "", errors.New("Apache 配置超过 2 MiB")
	}
	for _, cfg := range []core.WAFConfig{previous, next} {
		if _, err := core.DecodeApacheWAFNativeBodyConfig(core.WAFSettings(cfg)); err != nil {
			return "", err
		}
	}
	bindings, err := apacheWAFBindings(source)
	if err != nil || len(bindings) == 0 {
		return "", errors.New("Apache 受管站点无法核实")
	}
	for _, id := range core.WAFScopedSites(next) {
		if len(bindings[id]) == 0 {
			return "", errors.New("Apache 请求体策略引用未运行或非受管站点")
		}
	}
	var sectionErr error
	base := apacheBodyHosts.ReplaceAllStringFunc(source, func(block string) string {
		if sectionErr != nil {
			return block
		}
		id := apacheBodySiteIdentity.FindStringSubmatch(block)
		if len(id) != 2 {
			sectionErr = errors.New("Apache 请求体站点身份不可核实")
			return block
		}
		old, e := apacheBodySiteBlock(previous, id[1])
		if e == nil {
			block, e = apacheBodyStripBlock(block, apacheBodySiteBegin, apacheBodySiteEnd, old)
		}
		sectionErr = e
		return block
	})
	if sectionErr != nil {
		return "", sectionErr
	}
	// Compute the old loader from the outside-only base, not from directives
	// inside the block being verified. This distinguishes an existing unique_id
	// load from the one owned exclusively by the native body feature.
	loaderBase := base
	if start := strings.Index(base, apacheBodyGlobalBegin); start >= 0 {
		end := strings.Index(base[start:], apacheBodyGlobalEnd)
		if end < 0 {
			return "", errors.New("Apache 请求体全局区块不完整")
		}
		loaderBase = base[:start] + base[start+end+len(apacheBodyGlobalEnd):]
	}
	old, err := apacheBodyGlobalBlock(previous, loaderBase)
	if err != nil {
		return "", err
	}
	base, err = apacheBodyStripBlock(base, apacheBodyGlobalBegin, apacheBodyGlobalEnd, old)
	if err != nil {
		return "", err
	}
	if strings.Contains(base, "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.MatchString(base) {
		return "", errors.New("Apache 含外部请求体模块、规则或未知受管标记，拒绝接管")
	}
	global, err := apacheBodyGlobalBlock(next, base)
	if err != nil {
		return "", err
	}
	if global != "" {
		base = strings.Replace(base, "# managed by panel\n", "# managed by panel\n"+global, 1)
	}
	base = apacheBodyHosts.ReplaceAllStringFunc(base, func(block string) string {
		id := apacheBodySiteIdentity.FindStringSubmatch(block)
		native, e := apacheBodySiteBlock(next, id[1])
		if e != nil {
			sectionErr = e
			return block
		}
		if native != "" {
			block = strings.Replace(block, "\n", "\n"+native, 1)
		}
		return block
	})
	if sectionErr != nil {
		return "", sectionErr
	}
	if len(base) > 2<<20 {
		return "", fmt.Errorf("Apache 请求体配置超过 2 MiB，未开始修改")
	}
	return base, nil
}
