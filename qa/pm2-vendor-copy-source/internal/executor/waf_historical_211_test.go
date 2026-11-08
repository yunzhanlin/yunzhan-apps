package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
)

// Captured by a read-only Go overlay from frozen 23r10 source (release inputs
// d7b68b4d1ffdececba0dd45e8d1b59bdd51f5c2bcfe75a4f27703e51c12b32c5).
// New nil/omitempty fields must not invalidate an existing signed installation.
func TestWAF211HistoricalBytesRemainPinned(t *testing.T) {
	for _, tc := range []struct{ kind, http, server, settings string }{
		{"default", "d84cf25e477c87851a4e7e02afacc547ba770d601a8688e86959bcfabb566987", "b2e4a3665dee7662ba98c04ac398f92ed21b4d811298e2ae49f24abb46e1199b", "8f7e0b0377ea575f1d9a18c1f416474c5b7bae0b7fd726b80f7ba542188118b5"},
		{"paused", "31577b42da313d1a27cfc04b0d0260bed081b250f2c0cd6e0955efb2ba79d425", "ac990e902fab8a651638c9f33ea3f1b6db42da805e13b655fc996a030eee0e2e", "235e397950c6d03227cb45883d42d0919f36ac70aa8b5656b2f6c83d12e1e5a5"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			cfg := core.DefaultWAFConfig()
			cfg.Policy.Revision = 11
			if tc.kind == "paused" {
				p := core.DefaultWAFBodyPolicy()
				p.Mode = "off"
				cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{{SiteID: strings.Repeat("b", 32), Policy: p}}}
				cfg.Policy.Lists["ua_deny"] = []core.WAFEntry{{ID: strings.Repeat("c", 32), Value: "scanner-2.2.0"}}
				cfg.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("d", 32), Path: "/old", Rate: 2, Burst: 3, Enabled: false}}
			}
			h, s := renderWAFPolicyVersion(cfg, "2.1.1")
			b, _ := json.Marshal(cfg)
			if core.Hash(h) != tc.http || core.Hash(s) != tc.server || core.Hash(string(b)) != tc.settings {
				t.Fatal("historical render/settings bytes changed")
			}
		})
	}
}

func TestWAFTrustedProxyOnlyRendersInOptedInServerScope(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.TrustedProxy = &core.WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"192.0.2.10/32", "2001:db8:100::/48"}, AcknowledgeHeaderControl: true}
	h, s := renderWAFPolicy(cfg)
	if strings.Contains(h, "set_real_ip_from") || strings.Contains(h, "real_ip_header") || strings.Contains(h, "real_ip_recursive") {
		t.Fatal("global trust escaped server scope")
	}
	for _, directive := range []string{"set_real_ip_from 192.0.2.10/32;", "set_real_ip_from 2001:db8:100::/48;", "real_ip_header X-Forwarded-For;", "real_ip_recursive on;"} {
		if strings.Count(s, directive) != 1 {
			t.Fatal("validated server directive missing/duplicated", directive)
		}
	}
	if !strings.Contains(h, `"ip":"$remote_addr","peer":"$realip_remote_addr"`) {
		t.Fatal("effective and original peer log identities not separated")
	}
	cfg.TrustedProxy.Enabled = false
	h, s = renderWAFPolicy(cfg)
	if strings.Contains(s, "set_real_ip_from") || strings.Contains(s, "real_ip_") || strings.Contains(h, "$realip_remote_addr") {
		t.Fatal("disabled managed policy retained trust/module dependency")
	}
}
