package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestWAFCCModeIsServerScopedOwnedAndReversible(t *testing.T) {
	id := strings.Repeat("a", 32)
	one := "server {\n  set $panel_waf_site " + id + ";\n  include /etc/panel/waf/server.d/*.conf;\n  location / { return 200 safe; }\n}\n"
	base := "# managed by panel; site=" + id + "\n" + one + one
	for _, mode := range []string{"block", "observe", "off"} {
		got, err := renderWAFCCSite(base, id, mode, true)
		if err != nil || strings.Count(got, wafCCSiteBegin+wafCCSiteLines(mode)+wafCCSiteEnd) != 2 {
			t.Fatal("each HTTP/TLS server needs its literal scoped mode", mode, err, got)
		}
		again, err := renderWAFCCSite(got, id, mode, true)
		if err != nil || again != got {
			t.Fatal("mode not idempotent", err)
		}
		removed, err := renderWAFCCSite(got, id, mode, false)
		if err != nil || removed != base {
			t.Fatal("removal changed unrelated site bytes", err)
		}
	}
	for _, suffix := range []string{"; disabled", "; panel-waf-disabled"} {
		paused := strings.Replace(base, "site="+id, "site="+id+suffix, 1)
		got, err := renderWAFCCSite(paused, id, "observe", true)
		if err != nil || got != paused {
			t.Fatal("paused site activated", err)
		}
	}
}

func TestWAFCCObservationRefusesIndependentLimitersAndEditedMarkers(t *testing.T) {
	id := strings.Repeat("a", 32)
	base := "# managed by panel; site=" + id + "\nserver {\n  include /etc/panel/waf/server.d/*.conf;\n}\n"
	for _, extra := range []string{"  limit_req zone=admin;\n", "  limit_req_dry_run off;\n", "  include /etc/nginx/admin-security.conf;\n", "  location /admin { limit_req zone=admin; }\n", "  location /admin { include /etc/nginx/admin-security.conf; }\n", wafCCSiteBegin + "  limit_req_dry_run $pw_mode;\n" + wafCCSiteEnd, wafCCSiteBegin, wafCCSiteEnd} {
		content := strings.Replace(base, "server {\n", "server {\n"+extra, 1)
		if _, err := renderWAFCCSite(content, id, "observe", true); err == nil {
			t.Fatal("unsafe observation accepted", extra)
		}
	}
	if _, err := renderWAFCCSite(strings.ReplaceAll(base, "  include /etc/panel/waf/server.d/*.conf;\n", ""), id, "observe", true); err == nil {
		t.Fatal("missing unique server anchor accepted")
	}
}

func TestWAFCCObserveRenderAndHistorical220Bytes(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("b", 32), Path: "/login", Rate: 1, Burst: 1, Enabled: true}}
	old, oldServer := renderWAFPolicyVersion(cfg, "2.2.0")
	current, server := renderWAFPolicy(cfg)
	for _, expected := range []string{"s0:observe:0", "REJECTED_DRY_RUN", "DELAYED_DRY_RUN", "(?:block|observe):0:1:"} {
		if strings.Contains(old, expected) || !strings.Contains(current, expected) {
			t.Fatal("closed historical render did not preserve old behavior", expected)
		}
	}
	if strings.Contains(oldServer, "limit_req_dry_run") || strings.Contains(server, "limit_req_dry_run") {
		t.Fatal("shared server include must never change all sites to dry-run")
	}
	cfg.Policy.Mode = "off"
	cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: strings.Repeat("a", 32), Mode: "observe"}}
	if wafEffectiveMetadataMode(cfg, strings.Repeat("a", 32)) != "off" {
		t.Fatal("site observe bypassed global off")
	}
}
