package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestWAFProbeIsIndependentOfWebsiteTemplates(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.Policy.Revision = 7
	h, _ := renderWAFPolicy(cfg)
	if !strings.Contains(h, "server_name panel-waf-check.invalid;") || !strings.Contains(h, wafProbeValue(cfg)) || !strings.HasSuffix(h, "} }\n") {
		t.Fatal("loopback probe must be valid HTTP-context configuration with a real newline")
	}
	changed := cfg
	changed.Policy.Revision++
	if wafProbeValue(cfg) == wafProbeValue(changed) {
		t.Fatal("probe does not bind revision")
	}
	changed = core.DefaultWAFConfig()
	changed.Policy.Revision = 7
	changed.Profile = "strict"
	if wafProbeValue(cfg) == wafProbeValue(changed) {
		t.Fatal("probe does not bind policy")
	}
}
