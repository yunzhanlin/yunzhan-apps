package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

const apacheCCGlobalBegin = "# PANEL APACHE NATIVE CC GLOBAL BEGIN\n"
const apacheCCGlobalEnd = "# PANEL APACHE NATIVE CC GLOBAL END\n"
const apacheCCSiteBegin = "# PANEL APACHE NATIVE CC SITE BEGIN\n"
const apacheCCSiteEnd = "# PANEL APACHE NATIVE CC SITE END\n"

var apacheCCExternalDirective = regexp.MustCompile(`(?mi)^\s*(?:YunzhanCC[A-Za-z0-9_]*|LoadModule\s+yunzhan_cc_module|LoadModule\s+\S+\s+[^\n]*mod_yunzhan_cc\.so["']?)(?:\s|$)`)

func apacheNativeDirectivesPresent(source string) bool {
	return strings.Contains(source, "PANEL APACHE NATIVE BODY") || apacheBodyExternalDirective.MatchString(source) || strings.Contains(source, "PANEL APACHE NATIVE CC") || apacheCCExternalDirective.MatchString(source)
}

func apacheCCSitePolicy(cfg core.WAFConfig, id string) (string, int, int) {
	mode, enabled, rate, burst := cfg.Policy.Mode, cfg.Policy.CCEnabled, cfg.Rate, cfg.Policy.Burst
	for _, site := range cfg.Policy.Sites {
		if site.SiteID != id {
			continue
		}
		if cfg.Policy.Mode != "off" && site.Mode != "inherit" {
			mode = site.Mode
		}
		if site.CCEnabled != nil {
			enabled = *site.CCEnabled
		}
		if site.Rate != 0 {
			rate = site.Rate
		}
		if site.Burst != 0 {
			burst = site.Burst
		}
	}
	if !enabled {
		mode = "off"
	}
	return mode, rate, burst
}

// All vhosts share this complete CC-policy fingerprint, including the proxy
// identity contract. It excludes body policy and request bytes. Counter
// keys themselves use site, rule, effective rate/burst and canonical client;
// a harmless reload or observe/block change never restores burst allowances.
func apacheCCPolicyFingerprint(cfg core.WAFConfig) string {
	data, _ := json.Marshal(struct {
		Engine  *core.ApacheWAFCCConfig     `json:"engine"`
		Proxy   *core.WAFTrustedProxyConfig `json:"proxy"`
		Rate    int                         `json:"rate"`
		Mode    string                      `json:"mode"`
		Enabled bool                        `json:"enabled"`
		Burst   int                         `json:"burst"`
		Sites   []core.WAFSitePolicy        `json:"sites"`
		Rules   []core.WAFCCRule            `json:"rules"`
	}{cfg.ApacheCC, cfg.TrustedProxy, cfg.Rate, cfg.Policy.Mode, cfg.Policy.CCEnabled, cfg.Policy.Burst, cfg.Policy.Sites, cfg.Policy.CCRules})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func apacheCCGlobalBlock(cfg core.WAFConfig, bindings map[string][]string) (string, error) {
	if cfg.ApacheCC == nil {
		return "", nil
	}
	if !core.ValidID(cfg.ApacheCC.EngineJobID) {
		return "", errors.New("Apache CC 引擎任务标识无效")
	}
	active := 0
	for id := range bindings {
		mode, _, _ := apacheCCSitePolicy(cfg, id)
		if mode != "off" {
			active++
		}
	}
	if active > 64 {
		return "", errors.New("Apache 原生 CC 最多同时启用 64 个网站，其他站点可明确关闭 CC")
	}
	return apacheCCGlobalBegin + "LoadModule yunzhan_cc_module " + filepath.Join(apacheBodyEngines, cfg.ApacheCC.EngineJobID, "apache/mod_yunzhan_cc.so") + "\n" + apacheCCGlobalEnd, nil
}

func apacheCCSiteBlock(cfg core.WAFConfig, id string) (string, error) {
	if cfg.ApacheCC == nil {
		return "", nil
	}
	if !core.ValidID(id) {
		return "", errors.New("Apache CC 网站标识无效")
	}
	mode, rate, burst := apacheCCSitePolicy(cfg, id)
	var out strings.Builder
	out.WriteString(apacheCCSiteBegin)
	fmt.Fprintf(&out, "YunzhanCCSite %s %s %d %d %s\n", id, mode, rate, burst, apacheCCPolicyFingerprint(cfg))
	if mode != "off" {
		for _, rule := range cfg.Policy.CCRules {
			if !rule.Enabled || rule.SiteID != "" && rule.SiteID != id {
				continue
			}
			kind := "exact"
			if rule.Prefix {
				kind = "prefix"
			}
			fmt.Fprintf(&out, "YunzhanCCRule %s %s %s %d %d\n", rule.ID, hex.EncodeToString([]byte(rule.Path)), kind, rule.Rate, rule.Burst)
		}
	}
	out.WriteString(apacheCCSiteEnd)
	return out.String(), nil
}

func stripApacheCCSource(source string, previous core.WAFConfig) (string, error) {
	bindings, err := apacheWAFBindings(source)
	if err != nil {
		return "", err
	}
	var blockErr error
	base := apacheBodyHosts.ReplaceAllStringFunc(source, func(block string) string {
		if blockErr != nil {
			return block
		}
		id := apacheBodySiteIdentity.FindStringSubmatch(block)
		if len(id) != 2 {
			blockErr = errors.New("Apache CC 网站身份无法核验")
			return block
		}
		expected, e := apacheCCSiteBlock(previous, id[1])
		if e == nil {
			block, e = apacheBodyStripBlock(block, apacheCCSiteBegin, apacheCCSiteEnd, expected)
		}
		blockErr = e
		return block
	})
	if blockErr != nil {
		return "", fmt.Errorf("Apache CC 原挂载被修改、缺失或重复：%w", blockErr)
	}
	expected, err := apacheCCGlobalBlock(previous, bindings)
	if err != nil {
		return "", err
	}
	base, err = apacheBodyStripBlock(base, apacheCCGlobalBegin, apacheCCGlobalEnd, expected)
	if err != nil {
		return "", fmt.Errorf("Apache CC 原全局挂载不完整：%w", err)
	}
	if strings.Contains(base, "PANEL APACHE NATIVE CC") || apacheCCExternalDirective.MatchString(base) {
		return "", errors.New("Apache 存在外部 CC 模块、指令或未知受管标记，未接管")
	}
	return base, nil
}

// Both independent native features are contained in the original main Apache
// file. The existing exact three-file transaction/rollback allowlist is kept;
// CC never edits Nginx, standalone rule files or another site's configuration.
func transitionApacheBodySource(source string, previous, next core.WAFConfig) (string, error) {
	if len(source) > 2<<20 {
		return "", errors.New("Apache 配置超过 2 MiB")
	}
	for _, cfg := range []core.WAFConfig{previous, next} {
		if _, err := core.DecodeApacheWAFNativeCCConfig(core.WAFSettings(cfg)); err != nil {
			return "", err
		}
	}
	base, err := stripApacheCCSource(source, previous)
	if err != nil {
		return "", err
	}
	base, err = transitionApacheBodyOnlySource(base, previous, next)
	if err != nil {
		return "", err
	}
	bindings, err := apacheWAFBindings(base)
	if err != nil {
		return "", err
	}
	global, err := apacheCCGlobalBlock(next, bindings)
	if err != nil {
		return "", err
	}
	if global != "" {
		base = strings.Replace(base, "# managed by panel\n", "# managed by panel\n"+global, 1)
	}
	var blockErr error
	base = apacheBodyHosts.ReplaceAllStringFunc(base, func(block string) string {
		if blockErr != nil {
			return block
		}
		id := apacheBodySiteIdentity.FindStringSubmatch(block)
		if len(id) != 2 {
			blockErr = errors.New("Apache CC 新挂载网站身份无法核验")
			return block
		}
		section, e := apacheCCSiteBlock(next, id[1])
		blockErr = e
		if e == nil && section != "" {
			block = strings.Replace(block, "\n", "\n"+section, 1)
		}
		return block
	})
	if blockErr != nil {
		return "", blockErr
	}
	if len(base) > 2<<20 {
		return "", errors.New("Apache 请求体与 CC 生成配置超过 2 MiB")
	}
	return base, nil
}
