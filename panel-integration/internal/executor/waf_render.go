package executor

import (
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type wafMapEntry struct{ key, value string }

func wafProbeValue(cfg core.WAFConfig) string {
	b, _ := json.Marshal(cfg)
	return core.WAFVersion + ":" + strconv.FormatInt(cfg.Policy.Revision, 10) + ":" + core.Hash(string(b))
}

func wafQuote(value string) string { return strconv.Quote(value) }
func wafBool(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
func wafMap(out *strings.Builder, source, name, def string, entries []wafMapEntry) {
	fmt.Fprintf(out, "map %s $%s {\n  default %s;\n", wafQuote(source), name, def)
	for _, e := range entries {
		fmt.Fprintf(out, "  %s %s;\n", wafQuote(e.key), e.value)
	}
	out.WriteString("}\n")
}

func renderWAFPolicy(cfg core.WAFConfig) (string, string) {
	var http, server strings.Builder
	http.WriteString("# managed by panel nginx-waf " + core.WAFVersion + "; independently authored metadata rules\n")
	// map declares the variable even on a host without managed sites. Site
	// server blocks assign their immutable ID in rewrite phase before use.
	wafMap(&http, "$server_name", "panel_waf_site", wafQuote("unmanaged"), nil)
	ids := append([]string{""}, core.WAFScopedSites(cfg)...)
	policies := map[string]core.WAFSitePolicy{}
	for _, p := range cfg.Policy.Sites {
		policies[p.SiteID] = p
	}
	modeRows, scopeRows := []wafMapEntry{}, []wafMapEntry{}
	groupRows := map[string][]wafMapEntry{}
	ccOn := map[string]bool{}
	ccRows := []wafMapEntry{}
	rates, bursts := map[string]int{}, map[string]int{}
	for i, id := range ids {
		p := policies[id]
		mode := cfg.Policy.Mode
		if mode != "off" && p.Mode != "" && p.Mode != "inherit" {
			mode = p.Mode
		}
		key := fmt.Sprintf("s%d", i)
		scopeRows = append(scopeRows, wafMapEntry{id, wafQuote(key)})
		modeRows = append(modeRows, wafMapEntry{id, wafQuote(mode)})
		for _, g := range core.WAFGroupNames {
			enabled := cfg.Policy.Groups[g]
			if value, ok := p.Groups[g]; ok {
				enabled = value
			}
			groupRows[g] = append(groupRows[g], wafMapEntry{id, wafBool(enabled)})
		}
		cc := cfg.Policy.CCEnabled
		if p.CCEnabled != nil {
			cc = *p.CCEnabled
		}
		ccOn[key] = cc
		ccRows = append(ccRows, wafMapEntry{id, wafBool(cc)})
		rates[key] = cfg.Rate
		if p.Rate != 0 {
			rates[key] = p.Rate
		}
		bursts[key] = cfg.Policy.Burst
		if p.Burst != 0 {
			bursts[key] = p.Burst
		}
	}
	wafMap(&http, "$panel_waf_site", "pw_scope", wafQuote("s0"), scopeRows[1:])
	wafMap(&http, "$panel_waf_site", "pw_mode", modeRows[0].value, modeRows[1:])
	wafMap(&http, "$panel_waf_site", "pw_cc_enabled", ccRows[0].value, ccRows[1:])
	for _, g := range core.WAFGroupNames {
		wafMap(&http, "$panel_waf_site", "pw_on_"+g, groupRows[g][0].value, groupRows[g][1:])
	}
	for _, kind := range []string{"ip_allow", "ip_deny", "url_allow", "url_deny", "ua_allow", "ua_deny"} {
		rows := []wafMapEntry{}
		for i, id := range ids {
			name := fmt.Sprintf("pw_%s_s%d", kind, i)
			entries := []string{}
			seen := map[string]bool{}
			for _, x := range cfg.Policy.Lists[kind] {
				if (x.SiteID == "" || x.SiteID == id) && !seen[x.Value] {
					entries = append(entries, x.Value)
					seen[x.Value] = true
				}
			}
			sort.Strings(entries)
			if strings.HasPrefix(kind, "ip_") {
				fmt.Fprintf(&http, "geo $remote_addr $%s {\n  default 0;\n", name)
				for _, value := range entries {
					fmt.Fprintf(&http, "  %s 1;\n", value)
				}
				http.WriteString("}\n")
			} else {
				xs := []wafMapEntry{}
				source := "$uri"
				for _, value := range entries {
					pattern := "~^" + regexp.QuoteMeta(value)
					if strings.HasPrefix(kind, "ua_") {
						source = "$http_user_agent"
						pattern = "~*" + regexp.QuoteMeta(value)
					}
					xs = append(xs, wafMapEntry{pattern, "1"})
				}
				wafMap(&http, source, name, "0", xs)
			}
			if id != "" {
				rows = append(rows, wafMapEntry{id, "$" + name})
			}
		}
		wafMap(&http, "$panel_waf_site", "pw_"+kind, "$pw_"+kind+"_s0", rows)
	}
	wafMap(&http, "$uri", "pw_health", "0", []wafMapEntry{{`~^/__panel_health_[a-f0-9]{32}$`, "1"}})
	wafMap(&http, "$request_method", "pw_raw_method", "0", []wafMapEntry{{"TRACE", "1"}, {"TRACK", "1"}})
	patterns := core.WAFPatterns(cfg.Profile)
	for _, g := range []string{"sql", "xss", "command", "traversal", "scanner", "cookie"} {
		source := "$uri:$args"
		pattern := patterns[g]
		if g == "scanner" {
			source = "$http_user_agent"
		}
		if g == "cookie" {
			source = "$http_cookie"
			pattern = patterns["sql"] + "|" + patterns["xss"] + "|" + patterns["command"] + "|" + patterns["traversal"]
		}
		wafMap(&http, source, "pw_raw_"+g, "0", []wafMapEntry{{"~*" + pattern, "1"}})
	}
	blockReason, observeReason := wafQuote(""), wafQuote("")
	for i, r := range cfg.Policy.Rules {
		if !r.Enabled {
			continue
		}
		source := map[string]string{"uri": "$uri", "args": "$args", "method": "$request_method", "cookie": "$http_cookie", "user_agent": "$http_user_agent"}[r.Field]
		pattern := regexp.QuoteMeta(r.Value)
		switch r.Operator {
		case "exact":
			pattern = "^" + pattern + "$"
		case "prefix":
			pattern = "^" + pattern
		}
		name := fmt.Sprintf("pw_custom_%d", i)
		wafMap(&http, source, name+"_raw", "0", []wafMapEntry{{"~*" + pattern, "1"}})
		if r.SiteID != "" {
			wafMap(&http, "$panel_waf_site:$"+name+"_raw", name, "0", []wafMapEntry{{r.SiteID + ":1", "1"}})
		} else {
			wafMap(&http, "$"+name+"_raw", name, "0", []wafMapEntry{{"1", "1"}})
		}
		previous := blockReason
		if r.Action == "observe" {
			previous = observeReason
		}
		wafMap(&http, "$"+name, name+"_reason", previous, []wafMapEntry{{"1", wafQuote("custom-" + r.ID)}})
		if r.Action == "observe" {
			observeReason = "$" + name + "_reason"
		} else {
			blockReason = "$" + name + "_reason"
		}
	}
	for _, g := range []string{"cookie", "scanner", "traversal", "command", "xss", "sql", "method"} {
		wafMap(&http, "$pw_on_"+g+":$pw_raw_"+g, "pw_bad_"+g, "0", []wafMapEntry{{"1:1", "1"}})
		wafMap(&http, "$pw_bad_"+g, "pw_reason_"+g, blockReason, []wafMapEntry{{"1", wafQuote(g)}})
		blockReason = "$pw_reason_" + g
	}
	for _, kind := range []string{"url", "ua", "ip"} {
		wafMap(&http, "$pw_"+kind+"_allow:$pw_"+kind+"_deny", "pw_reason_"+kind, blockReason, []wafMapEntry{{"~^1:", wafQuote("")}, {"0:1", wafQuote(kind + "-deny")}})
		blockReason = "$pw_reason_" + kind
	}
	// Apply the same exceptions to observe-only custom rules. IP deny remains
	// above UA/URL allow; health probes never disappear during policy changes.
	wafMap(&http, "$pw_ip_allow:$pw_ua_allow:$pw_url_allow:$pw_health", "pw_exempt", "0", []wafMapEntry{{"~1", "1"}})
	wafMap(&http, blockReason, "pw_candidate", blockReason, []wafMapEntry{{"", observeReason}})
	wafMap(&http, "$pw_exempt", "pw_observe_exempt", observeReason, []wafMapEntry{{"1", wafQuote("")}})
	wafMap(&http, blockReason, "pw_candidate_safe", blockReason, []wafMapEntry{{"", "$pw_observe_exempt"}})
	wafMap(&http, "$pw_mode:$pw_health", "pw_visible_reason", "$pw_candidate_safe", []wafMapEntry{{"~^off:", wafQuote("")}, {"~:1$", wafQuote("")}})
	wafMap(&http, blockReason, "pw_has_block", "1", []wafMapEntry{{"", "0"}})
	wafMap(&http, "$pw_mode:$pw_health:$pw_has_block", "pw_block", "0", []wafMapEntry{{"block:0:1", "1"}})
	wafMap(&http, "$pw_block:$pw_visible_reason", "pw_method_block", "0", []wafMapEntry{{"1:method", "1"}})
	wafMap(&http, "$pw_visible_reason:$limit_req_status", "pw_event", "1", []wafMapEntry{{"~^:(?!REJECTED$)", "0"}})
	wafMap(&http, "$limit_req_status", "pw_log_reason", "$pw_visible_reason", []wafMapEntry{{"REJECTED", wafQuote("cc")}})
	wafMap(&http, "$pw_block:$limit_req_status", "pw_log_action", wafQuote("observe"), []wafMapEntry{{"~^1:", wafQuote("block")}, {"~:REJECTED$", wafQuote("block")}})
	// Legacy event fields stay readable, but no queries, cookies, user agents,
	// bodies or credentials are written to the security log.
	wafMap(&http, "$pw_bad_sql", "panel_waf_bad_args", "$pw_bad_sql", nil)
	wafMap(&http, "$pw_bad_traversal", "panel_waf_bad_uri", "$pw_bad_traversal", nil)
	wafMap(&http, "$pw_bad_method", "panel_waf_bad_method", "$pw_bad_method", nil)
	wafMap(&http, "$pw_bad_scanner", "panel_waf_bad_agent", "$pw_bad_scanner", nil)
	for i := range ids {
		scope := fmt.Sprintf("s%d", i)
		name := "panel_waf_per_ip_v2"
		if i > 0 {
			name = "panel_waf_site_" + strconv.Itoa(i)
		}
		rows := []wafMapEntry{}
		if ccOn[scope] {
			rows = append(rows, wafMapEntry{scope + ":block:0", wafQuote("$panel_waf_site:$binary_remote_addr")})
		}
		key := "pw_cc_key_" + scope
		wafMap(&http, "$pw_scope:$pw_mode:$pw_exempt", key, wafQuote(""), rows)
		fmt.Fprintf(&http, "limit_req_zone $%s zone=%s:1m rate=%dr/s;\n", key, name, rates[scope])
		fmt.Fprintf(&server, "limit_req zone=%s burst=%d nodelay;\n", name, bursts[scope])
	}
	for i, r := range cfg.Policy.CCRules {
		if !r.Enabled {
			continue
		}
		name := "pw_urlcc_" + strconv.Itoa(i)
		pattern := "^block:0:1:"
		if r.SiteID == "" {
			pattern += "[^:]+:"
		} else {
			pattern += r.SiteID + ":"
		}
		pattern += regexp.QuoteMeta(r.Path)
		if !r.Prefix {
			pattern += "$"
		}
		wafMap(&http, "$pw_mode:$pw_exempt:$pw_cc_enabled:$panel_waf_site:$uri", name, wafQuote(""), []wafMapEntry{{"~" + pattern, wafQuote("$panel_waf_site:$binary_remote_addr")}})
		fmt.Fprintf(&http, "limit_req_zone $%s zone=%s:512k rate=%dr/s;\n", name, name, r.Rate)
		fmt.Fprintf(&server, "limit_req zone=%s burst=%d nodelay;\n", name, r.Burst)
	}
	http.WriteString("log_format panel_waf escape=json '{\"time\":\"$time_iso8601\",\"site\":\"$server_name\",\"site_id\":\"$panel_waf_site\",\"ip\":\"$remote_addr\",\"status\":$status,\"method\":\"$request_method\",\"path\":\"$uri\",\"reason\":\"$pw_log_reason\",\"action\":\"$pw_log_action\",\"bad_method\":\"$panel_waf_bad_method\",\"bad_args\":\"$panel_waf_bad_args\",\"bad_uri\":\"$panel_waf_bad_uri\",\"bad_agent\":\"$panel_waf_bad_agent\",\"rate\":\"$limit_req_status\"}';\n")
	// A dedicated loopback virtual host proves the exact configuration loaded,
	// including installations whose legacy websites have no health route.
	fmt.Fprintf(&http, "server { listen 127.0.0.1:19101; server_name panel-waf-check.invalid; access_log off; location = /__panel_waf_check { default_type text/plain; return 200 %s; } location / { return 404; } }\n", wafQuote(wafProbeValue(cfg)))
	return http.String(), "# managed by panel nginx-waf " + core.WAFVersion + "\nif ($pw_method_block) { return 405; }\nif ($pw_block) { return 403; }\n" + server.String() + "limit_req_status 429;\naccess_log /var/log/nginx/panel-waf.log panel_waf if=$pw_event;\nadd_header X-Panel-WAF $pw_mode always;\nadd_header X-Panel-WAF-Revision " + strconv.FormatInt(cfg.Policy.Revision, 10) + " always;\n"
}
