package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestApacheWAFRendererScopesPrivacyAndLiteralSafety(t *testing.T) {
	id := strings.Repeat("a", 32)
	bindings, err := apacheWAFBindings("# managed by panel\n<VirtualHost 127.0.0.1:19080>\n ServerName test.example.test\n ServerAlias alias.example.test\n CustomLog /var/log/apache2/panel-" + id + ".access.log combined\n</VirtualHost>\n")
	if err != nil || len(bindings[id]) != 2 {
		t.Fatal(bindings, err)
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: id, Mode: "observe", Groups: map[string]bool{"sql": false}}}
	cfg.Policy.Rules = []core.WAFRule{{ID: strings.Repeat("b", 32), Name: "literal", SiteID: id, Field: "uri", Operator: "contains", Value: `/x" %1 ${evil}`, Action: "block", Enabled: true}}
	rules, err := renderApacheWAF(cfg, bindings)
	if err != nil || strings.Contains(rules, `${evil}`) || !strings.Contains(rules, "E=PANEL_AW_MODE:observe") || !strings.Contains(rules, "ENV:PANEL_AW_SITE}") {
		t.Fatal(rules, err)
	}
	log := rules[strings.LastIndex(rules, "CustomLog"):]
	for _, secret := range []string{"QUERY_STRING", "HTTP_COOKIE", "HTTP_USER_AGENT", "%r"} {
		if strings.Contains(log, secret) {
			t.Fatal("log retains sensitive metadata", log)
		}
	}
	if apacheWAFProbe(cfg) != apacheWAFProbe(cfg) {
		t.Fatal("unstable probe fingerprint")
	}
	cfg.Policy.Sites[0].SiteID = strings.Repeat("c", 32)
	if _, err = renderApacheWAF(cfg, bindings); err == nil {
		t.Fatal("unknown site accepted")
	}
}
