package core

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWAFPolicyClosedSchemaAndBounds(t *testing.T) {
	for _, raw := range []map[string]any{{"nginx": "return 200;"}, {"rate_per_second": 1}, {"policy": nil}, {"policy": map[string]any{"groups": nil}}, {"policy": map[string]any{"mode": "unknown"}}, {"policy": map[string]any{"groups": map[string]any{"unlimited": true}}}, {"policy": map[string]any{"rules": []any{map[string]any{"name": "raw", "value": ".*", "field": "request_body", "operator": "regex", "action": "block"}}}}} {
		if _, e := DecodeWAFConfig(raw); e == nil {
			t.Fatal("invalid policy accepted", raw)
		}
	}
	cfg := DefaultWAFConfig()
	cfg.Policy.Lists["ip_deny"] = []WAFEntry{{Value: "2001:db8::1/64"}, {Value: "192.0.2.7"}}
	v, e := DecodeWAFConfig(WAFSettings(cfg))
	if e != nil {
		t.Fatal(e)
	}
	if v.Policy.Lists["ip_deny"][0].Value != "2001:db8::/64" || v.Policy.Lists["ip_deny"][1].Value != "192.0.2.7/32" {
		t.Fatal("IP canonicalization failed", v)
	}
	cfg.Policy.Lists["ip_deny"] = append(cfg.Policy.Lists["ip_deny"], WAFEntry{Value: "192.0.2.7/32"})
	if _, e = DecodeWAFConfig(WAFSettings(cfg)); e == nil {
		t.Fatal("canonical duplicate accepted")
	}
	cfg = DefaultWAFConfig()
	cfg.Policy.Rules = []WAFRule{{Name: "injection literal", Value: `"; return 200; # $arg_x`, Field: "uri", Operator: "contains", Action: "block", Enabled: true}}
	if _, e = DecodeWAFConfig(WAFSettings(cfg)); e != nil {
		t.Fatal("literal data rejected", e)
	}
	cfg.Policy.Rules[0].Value = "bad\nline"
	if _, e = DecodeWAFConfig(WAFSettings(cfg)); e == nil {
		t.Fatal("control characters accepted")
	}
	cfg = DefaultWAFConfig()
	for i := 0; i < 65; i++ {
		cfg.Policy.Sites = append(cfg.Policy.Sites, WAFSitePolicy{SiteID: ID(), Mode: "inherit"})
	}
	if _, e = DecodeWAFConfig(WAFSettings(cfg)); e == nil {
		t.Fatal("unbounded sites accepted")
	}
}
func TestWAFReportFiltersLegacyAndPagination(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	id := strings.Repeat("a", 32)
	snapshot := WAFEventsPage{HasMore: true, Events: []WAFEvent{{Time: now.Add(-time.Minute).Format(time.RFC3339), Site: "a.test", SiteID: id, IP: "::1", Status: 403, Reason: "sql", Action: "block"}, {Time: now.Add(-2 * time.Minute).Format(time.RFC3339), Site: "a.test", SiteID: id, IP: "192.0.2.1", Status: 200, Reason: "scanner", Action: "observe"}, {Time: now.Add(-3 * time.Minute).Format(time.RFC3339), Site: "a.test", IP: "::1", Status: 429, Rate: "REJECTED"}, {Time: now.Add(-25 * time.Hour).Format(time.RFC3339), Site: "a.test", IP: "::1", Status: 403}}}
	out, e := BuildWAFReport(snapshot, url.Values{"site_id": {id}, "site_domain": {"a.test"}, "limit": {"1"}}, now)
	if e != nil {
		t.Fatal(e)
	}
	if out.Total != 3 || out.Blocked != 2 || out.Observed != 1 || out.Sources != 2 || !out.Partial || len(out.Events) != 1 {
		t.Fatal("unexpected actual report", out)
	}
	out, e = BuildWAFReport(snapshot, url.Values{"ip": {"::1"}, "rule": {"cc"}}, now)
	if e != nil || out.Total != 1 || out.Events[0].Action != "block" {
		t.Fatal("legacy CC filter failed", out, e)
	}
	for _, q := range []url.Values{{"page": {"0"}}, {"limit": {"99999"}}, {"file": {"/etc/shadow"}}, {"ip": {"example.com"}}, {"action": {"fake"}}} {
		if _, e = BuildWAFReport(snapshot, q, now); e == nil {
			t.Fatal("unsafe report query accepted", q)
		}
	}
}

func TestWAFReportCCDryRunNeverCountsAsBlocked(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	events := []WAFEvent{}
	for _, status := range []string{"REJECTED_DRY_RUN", "DELAYED_DRY_RUN", "REJECTED"} {
		events = append(events, WAFEvent{Time: now.Add(-time.Minute).Format(time.RFC3339), Site: "a.test", IP: "192.0.2.1", Rate: status})
	}
	out, err := BuildWAFReport(WAFEventsPage{Events: events}, url.Values{"rule": {"cc"}}, now)
	if err != nil || out.Total != 3 || out.Blocked != 1 || out.Observed != 2 {
		t.Fatal("dry-run report fabricated blocking", out, err)
	}
	observed, err := BuildWAFReport(WAFEventsPage{Events: events}, url.Values{"rule": {"cc"}, "action": {"observe"}}, now)
	if err != nil || observed.Total != 2 || observed.Blocked != 0 {
		t.Fatal("CC observation filtering", observed, err)
	}
}
