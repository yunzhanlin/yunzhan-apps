package executor

import (
	"strings"
	"testing"

	"local/panel/internal/core"
)

const apacheBodyConfigSiteA = "0123456789abcdef0123456789abcdef"
const apacheBodyConfigSiteB = "1123456789abcdef0123456789abcdef"
const apacheBodyConfigEngine = "2123456789abcdef0123456789abcdef"

func apacheBodyConfigFixture() (string, core.WAFConfig, core.WAFConfig) {
	base := "# managed by panel\n# untouched global comment\nLoadModule mpm_event_module /opt/panel/runtimes/apache/2.4.68/modules/mod_mpm_event.so\n"
	for _, site := range []struct{ id, domain string }{{apacheBodyConfigSiteA, "a.localhost"}, {apacheBodyConfigSiteB, "b.localhost"}} {
		base += "<VirtualHost 127.0.0.1:19080>\n  ServerName " + site.domain + "\n  SetEnvIfExpr \"true\" PANEL_AW_SITE=" + site.id + "\n  " + apacheWAFInclude + "  CustomLog /var/log/apache2/panel-" + site.id + ".access.log combined\n  # untouched site rewrite and PHP handler\n  DocumentRoot /srv/panel/sites/" + site.id + "/public\n</VirtualHost>\n"
	}
	previous := core.DefaultApacheWAFConfig()
	next := core.DefaultApacheWAFConfig()
	p := core.DefaultWAFBodyPolicy()
	p.Mode = "block"
	next.Body = &core.WAFBodyConfig{EngineJobID: apacheBodyConfigEngine, Sites: []core.WAFBodySitePolicy{{SiteID: apacheBodyConfigSiteA, Policy: p}}}
	return base, previous, next
}

func TestApacheBodyConfigurationClosedEnableReapplyDisablePreservesOutsideBytes(t *testing.T) {
	base, old, next := apacheBodyConfigFixture()
	enabled, err := transitionApacheBodySource(base, old, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{apacheBodyGlobalBegin, "LoadModule security2_module " + apacheBodyEngines + "/" + apacheBodyConfigEngine + "/apache/mod_security2.so\n", "SecRuleEngine Off\n", "SecRuleEngine On\n", "SecRequestBodyLimitAction Reject\n", "SecAction \"id:128000,phase:1,t:none,pass,nolog,setenv:PANEL_AW_SITE=" + apacheBodyConfigSiteA, "SecTmpDir " + apacheBodyTemporary + "/" + apacheBodyConfigSiteA} {
		if !strings.Contains(enabled, expected) {
			t.Fatal("missing reviewed directive", expected)
		}
	}
	if strings.Count(enabled, apacheBodySiteBegin) != 1 || strings.Count(enabled, "SecUnicodeMapFile") != 1 || strings.Count(enabled, "LoadModule unique_id_module") != 1 || strings.Contains(strings.Split(enabled, "ServerName b.localhost")[1], "SecRuleEngine On") {
		t.Fatal("unselected website or process-wide directives changed")
	}
	again, err := transitionApacheBodySource(enabled, next, next)
	if err != nil || enabled != again {
		t.Fatal("non-idempotent pure configuration", err)
	}
	disabled, err := transitionApacheBodySource(enabled, next, old)
	if err != nil || disabled != base {
		t.Fatal("disable changed outside bytes or retained any owned loader", err)
	}
	if _, err := core.DecodeApacheWAFConfig(core.WAFSettings(next)); err == nil {
		t.Fatal("metadata-only signed app implicitly gained candidate capability")
	}
	if _, err := core.DecodeApacheWAFNativeBodyConfig(core.WAFSettings(next)); err != nil {
		t.Fatal(err)
	}
}

func TestApacheBodyConfigurationEffectiveModesAndSeparateSites(t *testing.T) {
	for _, mode := range []string{"block", "observe", "off"} {
		for _, siteMode := range []string{"inherit", "block", "observe", "off"} {
			t.Run(mode+"-"+siteMode, func(t *testing.T) {
				base, old, next := apacheBodyConfigFixture()
				next.Policy.Mode = mode
				next.Policy.Sites = []core.WAFSitePolicy{{SiteID: apacheBodyConfigSiteA, Mode: siteMode}}
				actual, err := transitionApacheBodySource(base, old, next)
				if err != nil {
					t.Fatal(err)
				}
				policy, active := core.WAFEffectiveBodyPolicy(next, apacheBodyConfigSiteA)
				if !active {
					if actual != base {
						t.Fatal("off loaded native program or left directives")
					}
				} else if !strings.Contains(actual, "SecRuleEngine "+map[string]string{"block": "On", "observe": "DetectionOnly"}[policy.Mode]+"\n") {
					t.Fatal("wide/site observe or off was bypassed")
				}
			})
		}
	}
	base, old, next := apacheBodyConfigFixture()
	p := core.DefaultWAFBodyPolicy()
	next.Body.Sites = append(next.Body.Sites, core.WAFBodySitePolicy{SiteID: apacheBodyConfigSiteB, Policy: p})
	actual, err := transitionApacheBodySource(base, old, next)
	if err != nil || strings.Count(actual, apacheBodySiteBegin) != 2 || strings.Count(actual, "SecPcreMatchLimit 10000") != 1 || !strings.Contains(actual, "SecRuleEngine DetectionOnly\n") || !strings.Contains(actual, "SecRuleEngine On\n") {
		t.Fatal("two sites must have separate modes and global limits", err)
	}
}

func TestApacheBodyConfigurationForeignEditsAndUnknownProgramsRefused(t *testing.T) {
	base, old, next := apacheBodyConfigFixture()
	enabled, err := transitionApacheBodySource(base, old, next)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]string{
		"site-rule-edit":        strings.Replace(enabled, "SecAuditEngine Off", "SecAuditEngine On", 1),
		"loader-edit":           strings.Replace(enabled, "SecStatusEngine Off", "SecStatusEngine On", 1),
		"site-marker-missing":   strings.Replace(enabled, apacheBodySiteEnd, "", 1),
		"loader-marker-missing": strings.Replace(enabled, apacheBodyGlobalEnd, "", 1),
		"duplicate-global":      strings.Replace(enabled, apacheBodyGlobalBegin, apacheBodyGlobalBegin+apacheBodyGlobalBegin, 1),
		"duplicate-site":        strings.Replace(enabled, apacheBodySiteBegin, apacheBodySiteBegin+apacheBodySiteBegin, 1),
		"external-rule":         enabled + "SecRuleEngine On\n",
		"external-module":       enabled + "LoadModule security2_module /foreign/mod_security2.so\n",
		"module-alias":          enabled + "LoadModule foreign_module /foreign/mod_security2.so\n",
		"quoted-module-alias":   enabled + "LoadModule foreign_module \"/foreign/mod_security2.so\"\n",
		"unknown-marker":        enabled + "# UNKNOWN PANEL APACHE NATIVE BODY\n",
		"duplicate-site-id":     strings.Replace(enabled, "panel-"+apacheBodyConfigSiteB+".access", "panel-"+apacheBodyConfigSiteA+".access", 1),
	}
	for name, value := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := transitionApacheBodySource(value, next, old); err == nil {
				t.Fatal("foreign configuration was overwritten")
			}
		})
	}
	for _, bad := range []string{base + "SecRuleEngine Off\n", base + "LoadModule SECURITY2_MODULE /foreign/module.so\n", base + "# BEGIN PANEL APACHE NATIVE BODY\n", strings.Replace(base, "# managed by panel", "# unmanaged", 1), base + strings.Repeat(" ", 2<<20)} {
		if _, err := transitionApacheBodySource(bad, old, next); err == nil {
			t.Fatal("unmanaged body state accepted")
		}
	}
	next.Body.Sites[0].SiteID = strings.Repeat("f", 32)
	if _, err := transitionApacheBodySource(base, old, next); err == nil {
		t.Fatal("unknown site accepted")
	}
}

func TestApacheBodyConfigurationPreservesExistingUniqueIDModule(t *testing.T) {
	base, old, next := apacheBodyConfigFixture()
	base = strings.Replace(base, "# managed by panel\n", "# managed by panel\nLoadModule unique_id_module \"/opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so\"\n", 1)
	actual, err := transitionApacheBodySource(base, old, next)
	if err != nil || strings.Count(actual, "LoadModule unique_id_module") != 1 {
		t.Fatal("existing fixed module was duplicated", err)
	}
	back, err := transitionApacheBodySource(actual, next, old)
	if err != nil || back != base {
		t.Fatal("existing independent module was removed", err)
	}
	for _, bad := range []string{strings.Replace(base, "mod_unique_id.so", "foreign.so", 1), base + "LoadModule unique_id_module /opt/panel/runtimes/apache/2.4.68/modules/mod_unique_id.so\n"} {
		if _, err := transitionApacheBodySource(bad, old, next); err == nil {
			t.Fatal("unknown/duplicate prerequisite module accepted")
		}
	}
}
