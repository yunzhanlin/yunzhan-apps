package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Closed future2.6 policy DTO ONLY. Current WAF2.5.2 still has no country
// field/handler and cannot activate this by accepting a newer version label.
// Shape validation does NOT grant file, signature or installation authority.
type WAFCountryDataset struct {
	Dataset         string   `json:"dataset"`
	DataManifestSHA string   `json:"data_manifest_sha256"`
	Release         string   `json:"release"`
	Revision        int      `json:"revision"`
	Countries       []string `json:"countries"`
}
type WAFCountryRule struct {
	Mode      string   `json:"mode"`
	List      string   `json:"list"`
	Countries []string `json:"countries"`
}
type WAFCountrySite struct {
	SiteID string         `json:"site_id"`
	Rule   WAFCountryRule `json:"rule"`
}
type WAFCountryConfig struct {
	Enabled bool              `json:"enabled"`
	Data    WAFCountryDataset `json:"data"`
	Global  WAFCountryRule    `json:"global"`
	Sites   []WAFCountrySite  `json:"sites"`
}

func wafCountryCodesValid(codes []string, empty bool) bool {
	if codes == nil || len(codes) > 32 || !empty && len(codes) == 0 {
		return false
	}
	previous := ""
	for _, code := range codes {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || code <= previous {
			return false
		}
		previous = code
	}
	return true
}

func WAFCountryDatasetID(data WAFCountryDataset) string {
	if !validLowerSHA256(data.DataManifestSHA) || !wafCountryCodesValid(data.Countries, false) {
		return ""
	}
	raw, _ := json.Marshal(data.Countries)
	return data.DataManifestSHA + "-" + Hash(string(raw))
}

func wafCountryRuleValid(rule WAFCountryRule, site bool, selected map[string]bool) bool {
	if !wafCountryCodesValid(rule.Countries, true) {
		return false
	}
	if rule.Mode == "off" || site && rule.Mode == "inherit" {
		return rule.List == "" && len(rule.Countries) == 0
	}
	if rule.Mode != "block" && rule.Mode != "observe" || rule.List != "allow" && rule.List != "deny" || len(rule.Countries) == 0 {
		return false
	}
	for _, code := range rule.Countries {
		if !selected[code] {
			return false
		}
	}
	return true
}

func ValidateWAFCountryConfig(cfg *WAFCountryConfig) error {
	if cfg == nil {
		return nil
	}
	bad := errors.New("国家策略仅允许完整已签名数据集引用、排序国家集合及明确的停用/观察/阻断/站点继承；不得指定文件或未知地区动作")
	data := cfg.Data
	if data.Dataset == "" || data.Dataset != WAFCountryDatasetID(data) || !statisticsGeoMonth.MatchString(data.Release) || data.Revision < 1 || data.Revision > 1000 || cfg.Sites == nil || len(cfg.Sites) > 64 {
		return bad
	}
	selected := make(map[string]bool, len(data.Countries))
	for _, code := range data.Countries {
		selected[code] = true
	}
	if !wafCountryRuleValid(cfg.Global, false, selected) {
		return bad
	}
	previous := ""
	for _, site := range cfg.Sites {
		if !ValidID(site.SiteID) || site.SiteID <= previous || !wafCountryRuleValid(site.Rule, true, selected) {
			return bad
		}
		previous = site.SiteID
	}
	return nil
}

func DecodeWAFCountryConfig(raw []byte) (WAFCountryConfig, error) {
	var empty WAFCountryConfig
	bad := errors.New("国家策略含缺失、重复、未知、别名或空值字段")
	var shape struct {
		Enabled json.RawMessage   `json:"enabled"`
		Data    json.RawMessage   `json:"data"`
		Global  json.RawMessage   `json:"global"`
		Sites   []json.RawMessage `json:"sites"`
	}
	if len(raw) < 1 || len(raw) > 32<<10 || !wafInventoryJSONShape(raw, []string{"enabled", "data", "global", "sites"}) || json.Unmarshal(raw, &shape) != nil || !bytes.Equal(shape.Enabled, []byte("true")) && !bytes.Equal(shape.Enabled, []byte("false")) || !wafInventoryJSONShape(shape.Data, []string{"dataset", "data_manifest_sha256", "release", "revision", "countries"}) || !wafInventoryJSONShape(shape.Global, []string{"mode", "list", "countries"}) {
		return empty, bad
	}
	for _, site := range shape.Sites {
		var wire struct {
			Rule json.RawMessage `json:"rule"`
		}
		if !wafInventoryJSONShape(site, []string{"site_id", "rule"}) || json.Unmarshal(site, &wire) != nil || !wafInventoryJSONShape(wire.Rule, []string{"mode", "list", "countries"}) {
			return empty, bad
		}
	}
	var cfg WAFCountryConfig
	if json.Unmarshal(raw, &cfg) != nil || ValidateWAFCountryConfig(&cfg) != nil {
		return empty, bad
	}
	return cfg, nil
}

// A country block can never promote an existing site from observe/off to
// blocking. Health/allowlist exceptions are applied by the existing renderer.
func WAFCountryEffectiveRule(cfg *WAFCountryConfig, siteID, metadataMode string) (WAFCountryRule, error) {
	off := WAFCountryRule{Mode: "off", Countries: []string{}}
	if ValidateWAFCountryConfig(cfg) != nil || siteID != "" && !ValidID(siteID) || metadataMode != "block" && metadataMode != "observe" && metadataMode != "off" {
		return off, errors.New("国家策略生效范围或主防护模式无法核对")
	}
	if cfg == nil || !cfg.Enabled || metadataMode == "off" {
		return off, nil
	}
	rule := cfg.Global
	for _, site := range cfg.Sites {
		if site.SiteID == siteID && site.Rule.Mode != "inherit" {
			rule = site.Rule
			break
		}
	}
	if rule.Mode == "block" && metadataMode == "observe" {
		rule.Mode = "observe"
	}
	rule.Countries = append([]string{}, rule.Countries...)
	return rule, nil
}

// '--' means NON-MATCH in the selected signed dataset, not an independently
// established unknown country. Allowlist rejects it; denylist permits it.
// This returns a candidate, NOT proof that Nginx blocked a real request.
func WAFCountryRuleWouldReject(rule WAFCountryRule, country string) (bool, error) {
	selected := map[string]bool{}
	for _, code := range rule.Countries {
		selected[code] = true
	}
	if !wafCountryRuleValid(rule, false, selected) || country != "--" && (len(country) != 2 || strings.Trim(country, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" || country == "ZZ") {
		return false, errors.New("国家策略或原数据标签无效")
	}
	if rule.Mode == "off" {
		return false, nil
	}
	matched := selected[country]
	if rule.List == "allow" {
		return !matched, nil
	}
	return matched, nil
}
