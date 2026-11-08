package executor

import (
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestWAFHealthBindingIsVersionedAndRequiresCurrentSiteIdentity(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	old, _ := renderWAFPolicyVersion(cfg, "2.5.1")
	if !strings.Contains(old, `map "$uri" $pw_health`) || !strings.Contains(old, `~^/__panel_health_[a-f0-9]{32}$`) {
		t.Fatal("historical renderer changed; original source cannot be independently verified")
	}
	for _, version := range []string{"2.5.2", core.WAFCountryDataVersion} {
		fixed, _ := renderWAFPolicyVersion(cfg, version)
		if !strings.Contains(fixed, `map "$panel_waf_site:$uri" $pw_health`) || !strings.Contains(fixed, `~^([a-f0-9]{32}):/__panel_health_\\1$`) || strings.Contains(fixed, `~^/__panel_health_[a-f0-9]{32}$`) {
			t.Fatal("future health exception not bound to actual site", version)
		}
	}
	for _, version := range []string{"2.5.1", "2.5.2-preview", "2.6.1", "future"} {
		if wafBoundHealthVersion(version) {
			t.Fatal("unknown/old version borrowed health handler", version)
		}
	}
}
