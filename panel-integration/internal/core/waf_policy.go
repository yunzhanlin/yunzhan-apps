package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode"
)

const WAFVersion = "2.0.0"

var WAFGroupNames = []string{"method", "sql", "xss", "command", "traversal", "scanner", "cookie"}

type WAFEntry struct {
	ID     string `json:"id"`
	Value  string `json:"value"`
	SiteID string `json:"site_id,omitempty"`
}
type WAFRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	SiteID   string `json:"site_id,omitempty"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}
type WAFSitePolicy struct {
	SiteID    string          `json:"site_id"`
	Mode      string          `json:"mode"`
	Rate      int             `json:"rate_per_second"`
	Burst     int             `json:"burst"`
	CCEnabled *bool           `json:"cc_enabled,omitempty"`
	Groups    map[string]bool `json:"groups,omitempty"`
}
type WAFCCRule struct {
	ID      string `json:"id"`
	SiteID  string `json:"site_id,omitempty"`
	Path    string `json:"path"`
	Prefix  bool   `json:"prefix"`
	Rate    int    `json:"rate_per_second"`
	Burst   int    `json:"burst"`
	Enabled bool   `json:"enabled"`
}
type WAFPolicy struct {
	Schema    int                   `json:"schema_version"`
	Revision  int64                 `json:"revision"`
	Mode      string                `json:"mode"`
	CCEnabled bool                  `json:"cc_enabled"`
	Burst     int                   `json:"burst"`
	Groups    map[string]bool       `json:"groups"`
	Lists     map[string][]WAFEntry `json:"lists"`
	Rules     []WAFRule             `json:"rules"`
	Sites     []WAFSitePolicy       `json:"sites"`
	CCRules   []WAFCCRule           `json:"cc_rules"`
}
type WAFConfig struct {
	Profile string    `json:"profile"`
	Rate    int       `json:"rate_per_second"`
	Policy  WAFPolicy `json:"policy"`
}

func DefaultWAFConfig() WAFConfig {
	v := WAFConfig{Profile: "balanced", Rate: 20, Policy: WAFPolicy{Schema: 2, Mode: "block", CCEnabled: true, Burst: 60, Groups: map[string]bool{}, Lists: map[string][]WAFEntry{}, Rules: []WAFRule{}, Sites: []WAFSitePolicy{}, CCRules: []WAFCCRule{}}}
	for _, g := range WAFGroupNames {
		v.Policy.Groups[g] = g != "cookie"
	}
	for _, k := range []string{"ip_allow", "ip_deny", "url_allow", "url_deny", "ua_allow", "ua_deny"} {
		v.Policy.Lists[k] = []WAFEntry{}
	}
	return v
}
func WAFSettings(v WAFConfig) map[string]any {
	b, _ := json.Marshal(v)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return out
}
func DecodeWAFConfig(raw map[string]any) (WAFConfig, error) {
	v := DefaultWAFConfig()
	if raw == nil {
		return v, nil
	}
	b, e := json.Marshal(raw)
	if e != nil || len(b) > 128<<10 {
		return v, errors.New("WAF 配置超过 128 KiB 或格式无效")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var input any
	if json.Unmarshal(b, &input) != nil || wafHasNull(input) {
		return v, errors.New("WAF 配置不接受 null 字段，请省略可选字段或填写明确值")
	}
	d.DisallowUnknownFields()
	if e = d.Decode(&v); e != nil {
		return v, fmt.Errorf("WAF 配置包含未知字段或类型错误：%w", e)
	}
	if v.Profile != "balanced" && v.Profile != "strict" || v.Rate < 5 || v.Rate > 200 {
		return v, errors.New("防护级别为 balanced/strict，默认速率为 5–200 次/秒")
	}
	if v.Policy.Schema != 2 || v.Policy.Revision < 0 || !wafMode(v.Policy.Mode, false) || v.Policy.Burst < 1 || v.Policy.Burst > 1000 {
		return v, errors.New("WAF 版本、修订号、模式或突发容量无效")
	}
	groupOK := func(groups map[string]bool) bool {
		for k := range groups {
			if !containsString(WAFGroupNames, k) {
				return false
			}
		}
		return true
	}
	if !groupOK(v.Policy.Groups) {
		return v, errors.New("未知防护规则分类")
	}
	if len(v.Policy.Sites) > 64 || len(v.Policy.Rules) > 64 || len(v.Policy.CCRules) > 20 {
		return v, errors.New("站点策略最多 64 条，自定义规则最多 64 条，URL CC 规则最多 20 条")
	}
	seenSites := map[string]bool{}
	for _, p := range v.Policy.Sites {
		if !ValidID(p.SiteID) || seenSites[p.SiteID] || !wafMode(p.Mode, true) || p.Rate != 0 && (p.Rate < 5 || p.Rate > 200) || p.Burst < 0 || p.Burst > 1000 || !groupOK(p.Groups) {
			return v, errors.New("站点策略标识重复或参数无效")
		}
		seenSites[p.SiteID] = true
	}
	listKeys := []string{"ip_allow", "ip_deny", "url_allow", "url_deny", "ua_allow", "ua_deny"}
	total := 0
	for kind, entries := range v.Policy.Lists {
		if !containsString(listKeys, kind) {
			return v, errors.New("未知名单分类")
		}
		seen := map[string]bool{}
		for i := range entries {
			x := &entries[i]
			x.Value = strings.TrimSpace(x.Value)
			if x.SiteID != "" && !ValidID(x.SiteID) || !wafText(x.Value, 256) {
				return v, errors.New("名单范围或内容无效")
			}
			if strings.HasPrefix(kind, "ip_") {
				if a, e := netip.ParseAddr(x.Value); e == nil {
					x.Value = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
				} else if p, e := netip.ParsePrefix(x.Value); e == nil && !p.Addr().Is4In6() {
					x.Value = p.Masked().String()
				} else {
					return v, errors.New("IP 名单仅接受 IPv4、IPv6 或 CIDR，不接受域名")
				}
			} else if strings.HasPrefix(kind, "url_") && (!strings.HasPrefix(x.Value, "/") || strings.ContainsAny(x.Value, "?#")) {
				return v, errors.New("URL 名单为不含查询参数的路径前缀，例如 /api/login")
			}
			if x.ID == "" {
				x.ID = Hash(kind + "|" + x.SiteID + "|" + x.Value)[:32]
			}
			key := x.SiteID + "|" + x.Value
			if !ValidID(x.ID) || seen[key] {
				return v, errors.New("名单标识无效或内容重复")
			}
			seen[key] = true
		}
		v.Policy.Lists[kind] = entries
		total += len(entries)
	}
	if total > 500 {
		return v, errors.New("全部名单最多 500 条")
	}
	seenRules := map[string]bool{}
	for i := range v.Policy.Rules {
		r := &v.Policy.Rules[i]
		if !wafText(r.Name, 80) || !wafText(r.Value, 256) || r.SiteID != "" && !ValidID(r.SiteID) || !containsString([]string{"uri", "args", "user_agent", "method", "cookie"}, r.Field) || !containsString([]string{"exact", "prefix", "contains"}, r.Operator) || !containsString([]string{"block", "observe"}, r.Action) {
			return v, errors.New("自定义规则仅允许固定字段、字面匹配及阻断/记录动作；禁止原始 Nginx 和任意正则")
		}
		if r.ID == "" {
			r.ID = Hash(r.SiteID + "|" + r.Name + "|" + r.Field + "|" + r.Operator + "|" + r.Value + "|" + r.Action)[:32]
		}
		if !ValidID(r.ID) || seenRules[r.ID] {
			return v, errors.New("自定义规则标识无效或重复")
		}
		seenRules[r.ID] = true
	}
	seenCC := map[string]bool{}
	for i := range v.Policy.CCRules {
		r := &v.Policy.CCRules[i]
		if !wafText(r.Path, 256) || !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#") || r.SiteID != "" && !ValidID(r.SiteID) || r.Rate < 1 || r.Rate > 200 || r.Burst < 1 || r.Burst > 1000 {
			return v, errors.New("URL CC 规则要求有效路径、1–200 次/秒和 1–1000 突发容量")
		}
		if r.ID == "" {
			r.ID = Hash(r.SiteID + "|" + r.Path + fmt.Sprint(r.Prefix))[:32]
		}
		if !ValidID(r.ID) || seenCC[r.ID] {
			return v, errors.New("URL CC 规则标识无效或重复")
		}
		seenCC[r.ID] = true
	}
	if len(WAFScopedSites(v)) > 64 {
		return v, errors.New("全部配置涉及的独立站点最多 64 个")
	}
	return v, nil
}
func wafMode(mode string, inherit bool) bool {
	return mode == "block" || mode == "observe" || mode == "off" || inherit && mode == "inherit"
}
func wafHasNull(value any) bool {
	if value == nil {
		return true
	}
	switch v := value.(type) {
	case map[string]any:
		for _, x := range v {
			if wafHasNull(x) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if wafHasNull(x) {
				return true
			}
		}
	}
	return false
}
func wafText(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func containsString(list []string, s string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}
func WAFScopedSites(v WAFConfig) []string {
	ids := map[string]bool{}
	for _, p := range v.Policy.Sites {
		ids[p.SiteID] = true
	}
	for _, xs := range v.Policy.Lists {
		for _, x := range xs {
			if x.SiteID != "" {
				ids[x.SiteID] = true
			}
		}
	}
	for _, r := range v.Policy.Rules {
		if r.SiteID != "" {
			ids[r.SiteID] = true
		}
	}
	for _, r := range v.Policy.CCRules {
		if r.SiteID != "" {
			ids[r.SiteID] = true
		}
	}
	out := []string{}
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
func (s *Store) validateWAFSites(v WAFConfig) error {
	for _, id := range WAFScopedSites(v) {
		if _, e := s.Site(id); e != nil {
			return errors.New("WAF 配置引用不存在或已归档的网站，请删除失效策略后重试")
		}
	}
	return nil
}

// Independent built-ins inspect request metadata only, not a full semantic WAF.
// Rules are intentionally public and versioned instead of claiming vendor parity.
func WAFPatterns(profile string) map[string]string {
	p := map[string]string{
		"sql":       `(?:union(?:\s|\+|%20|%09)+select|(?:sleep|benchmark)(?:\s|%20)*\()`,
		"xss":       `(?:(?:<|%3c)(?:script|iframe)|(?:javascript|vbscript)(?::|%3a))`,
		"command":   `(?:base64_decode|(?:eval|assert)(?:\s|%20)*\(|(?:;|%3b|\||%7c)(?:\s|\+|%20)*(?:wget|curl|bash|sh)(?:\s|\+|%20))`,
		"traversal": `(?:/etc/passwd|(?:\.\.|%2e%2e)(?:/|%2f|%5c)|(?:/|%2f)(?:\.git|\.env)(?:/|%2f|$|\?))`,
		"scanner":   `(?:sqlmap|nikto|masscan|nmap|acunetix|nessus|wpscan)`,
	}
	if profile == "strict" {
		p["sql"] += `|select(?:\s|\+|%20)+.{0,120}(?:\s|\+|%20)+from`
		p["xss"] += `|(?:onerror|onload)(?:\s|%20)*(?:=|%3d)`
		p["scanner"] += `|zgrab|dirbuster|gobuster`
	}
	return p
}
