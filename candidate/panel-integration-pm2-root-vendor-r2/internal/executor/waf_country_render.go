package executor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"local/panel/internal/core"
)

const wafCountryDataRoot = "/var/lib/panel-executor/waf-country-data"

// PURE rendering only, not file/data/installation authorization. The ordinary
// Root policy transaction must independently verify ALL immutable cache bytes
// under the original key before using this fixed-prefix include configuration.
// Current2.5.2 does not call this future2.6 renderer or accept a country field.
func renderWAFCountryMaps(cfg *core.WAFCountryConfig, masterMode string) (string, bool, error) {
	if masterMode != "off" && masterMode != "observe" && masterMode != "block" || core.ValidateWAFCountryConfig(cfg) != nil {
		return "", false, errors.New("国家原生规则或主防护模式未完整验证")
	}
	if cfg == nil || !cfg.Enabled || masterMode == "off" {
		return "", false, nil
	}
	active := cfg.Global.Mode != "off"
	for _, site := range cfg.Sites {
		active = active || site.Rule.Mode == "block" || site.Rule.Mode == "observe"
	}
	if !active {
		return "", false, nil // Stop removes the data includes, not its cache.
	}
	var out strings.Builder
	out.WriteString("# original signed country data; '--' is non-match, NOT an unknown-country assertion\n")
	out.WriteString("geo $remote_addr $pw_country_label {\n  default \"--\";\n")
	for _, code := range cfg.Data.Countries {
		fmt.Fprintf(&out, "  include %s;\n", wafQuote(wafCountryDataRoot+"/"+cfg.Data.Dataset+"/"+code+".cidr"))
	}
	out.WriteString("}\n")
	makeRule := func(rule core.WAFCountryRule, index int) string {
		if rule.Mode == "off" {
			return "0"
		}
		name := "pw_country_reject_" + strconv.Itoa(index)
		def, value := "0", "1"
		if rule.List == "allow" {
			def, value = "1", "0"
		}
		rows := make([]wafMapEntry, 0, len(rule.Countries))
		for _, code := range rule.Countries {
			rows = append(rows, wafMapEntry{code, value})
		}
		wafMap(&out, "$pw_country_label", name, def, rows)
		return "$" + name
	}
	defaultReject := makeRule(cfg.Global, 0)
	modeRows, rejectRows := []wafMapEntry{}, []wafMapEntry{}
	for i, site := range cfg.Sites {
		if site.Rule.Mode == "inherit" {
			continue
		}
		modeRows = append(modeRows, wafMapEntry{site.SiteID, wafQuote(site.Rule.Mode)})
		rejectRows = append(rejectRows, wafMapEntry{site.SiteID, makeRule(site.Rule, i+1)})
	}
	wafMap(&out, "$panel_waf_site", "pw_country_mode", wafQuote(cfg.Global.Mode), modeRows)
	wafMap(&out, "$panel_waf_site", "pw_country_candidate", defaultReject, rejectRows)
	// Feed these reasons BELOW the established list/health exemptions and
	// built-in/custom priorities. No independent return directive bypasses the
	// existing final $pw_mode observe/off and per-site enforcement contract.
	wafMap(&out, "$pw_country_mode:$pw_country_candidate", "pw_country_block_reason", wafQuote(""), []wafMapEntry{{"block:1", wafQuote("country")}})
	wafMap(&out, "$pw_country_mode:$pw_country_candidate", "pw_country_observe_reason", wafQuote(""), []wafMapEntry{{"observe:1", wafQuote("country")}})
	return out.String(), true, nil
}
