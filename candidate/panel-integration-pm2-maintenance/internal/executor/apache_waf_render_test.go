package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestApacheWAFLegacyIntegrityOracleKeepsVersionAndOldLogShape(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	initial, err := renderApacheWAFVersion(cfg, map[string][]string{}, "1.0")
	if err != nil || core.Hash(initial) != "daabad5cc79ad1c307ed824fafd42f28f5d21aa176384ef5c3e48867130e613f" || apacheWAFProbeVersion(cfg, "1.0") != "active" {
		t.Fatal("initial fixed rule oracle changed", err)
	}
	changed := cfg
	changed.Profile = "strict"
	if _, err := renderApacheWAFVersion(changed, map[string][]string{}, "1.0"); err == nil {
		t.Fatal("non-default policy claimed initial version")
	}
	old, err := renderApacheWAFVersion(cfg, map[string][]string{}, "2.0.0")
	if err != nil || !strings.HasPrefix(old, "# managed by panel apache-waf 2.0.0;") || !strings.Contains(old, apacheWAFProbeVersion(cfg, "2.0.0")) || strings.Contains(old, `%{c}a`) || strings.Contains(old, `peer`) {
		t.Fatal("old integrity oracle drifted", old, err)
	}
	current, err := renderApacheWAF(cfg, map[string][]string{})
	if err != nil || !strings.Contains(current, `%{c}a`) || !strings.Contains(current, apacheWAFProbe(cfg)) {
		t.Fatal(current, err)
	}
	if _, err := renderApacheWAFVersion(cfg, map[string][]string{}, "1.9.0"); err == nil {
		t.Fatal("unknown old version accepted")
	}
	cfg.TrustedProxy = apacheTrustedProxyFixture()
	if old, err := renderApacheWAFVersion(cfg, map[string][]string{}, "2.1.0"); err != nil || !strings.Contains(old, apacheWAFProbeVersion(cfg, "2.1.0")) || !strings.Contains(old, "RemoteIPHeader X-Forwarded-For") || !strings.Contains(old, "%{c}a") {
		t.Fatal("known 2.1 signed migration oracle lost trust or dual identity", err)
	}
	if _, err := renderApacheWAFVersion(cfg, map[string][]string{}, "2.0.0"); err == nil {
		t.Fatal("new identity policy claimed legacy integrity")
	}
}

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
