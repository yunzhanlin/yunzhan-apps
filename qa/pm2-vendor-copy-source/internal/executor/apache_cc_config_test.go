package executor

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func apacheCCConfigFixture() (string, core.WAFConfig, core.WAFConfig) {
	base, old, next := apacheBodyConfigFixture()
	next.ApacheCC = &core.ApacheWAFCCConfig{EngineJobID: apacheBodyConfigEngine}
	next.Policy.CCEnabled = true
	next.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("a", 32), SiteID: apacheBodyConfigSiteA, Path: "/login", Rate: 1, Burst: 2, Enabled: true}}
	return base, old, next
}

func TestApacheCCThreeFileSectionsCoexistAndRemoveOnlyTheirOwnBytes(t *testing.T) {
	base, old, next := apacheCCConfigFixture()
	bodyOnly := next
	bodyOnly.ApacheCC = nil
	bodyOnly.Policy.CCEnabled = false
	bodyOnly.Policy.CCRules = []core.WAFCCRule{}
	original, err := transitionApacheBodySource(base, old, bodyOnly)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := transitionApacheBodySource(original, bodyOnly, next)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(combined, apacheCCGlobalBegin) != 1 || strings.Count(combined, apacheCCSiteBegin) != 2 || strings.Count(combined, apacheBodySiteBegin) != 1 {
		t.Fatal("a CC or existing body section is missing/duplicated")
	}
	if !strings.Contains(combined, "YunzhanCCRule "+strings.Repeat("a", 32)+" "+hex.EncodeToString([]byte("/login"))+" exact 1 2\n") {
		t.Fatal("literal URL rule was not encoded as data")
	}
	if strings.Count(combined, "YunzhanCCRule ") != 1 {
		t.Fatal("scoped URL rule leaked into the other site")
	}
	if again, err := transitionApacheBodySource(combined, next, next); err != nil || again != combined {
		t.Fatal("pure reapply changed the generation", err)
	}
	if back, err := transitionApacheBodySource(combined, next, bodyOnly); err != nil || back != original {
		t.Fatal("removing CC changed body engine or outside bytes", err)
	}
	if back, err := transitionApacheBodySource(combined, next, old); err != nil || back != base {
		t.Fatal("removing both features changed a PHP/rewrite/comment byte", err)
	}
	bindings, _ := apacheWAFBindings(combined)
	if _, err := renderApacheWAFVersion(next, bindings, core.ApacheWAFNativeBodyVersion); err == nil {
		t.Fatal("2.4 renderer silently adopted CC")
	}
	if _, err := renderApacheWAFVersion(next, bindings, core.ApacheWAFNativeCCVersion); err != nil {
		t.Fatal(err)
	}
}

func TestApacheCCGlobalOffAndIndependentSiteModesRates(t *testing.T) {
	for _, global := range []string{"off", "observe", "block"} {
		for _, siteMode := range []string{"inherit", "off", "observe", "block"} {
			t.Run(global+"/"+siteMode, func(t *testing.T) {
				base, old, next := apacheCCConfigFixture()
				next.Policy.Mode = global
				next.Policy.Sites = []core.WAFSitePolicy{{SiteID: apacheBodyConfigSiteA, Mode: siteMode, Rate: 7, Burst: 9}}
				out, err := transitionApacheBodySource(base, old, next)
				if err != nil {
					t.Fatal(err)
				}
				expect := siteMode
				if expect == "inherit" {
					expect = global
				}
				if global == "off" {
					expect = "off"
				}
				if !strings.Contains(out, fmt.Sprintf("YunzhanCCSite %s %s 7 9 ", apacheBodyConfigSiteA, expect)) {
					t.Fatal("global off or site override lost")
				}
				if !strings.Contains(out, fmt.Sprintf("YunzhanCCSite %s %s 20 60 ", apacheBodyConfigSiteB, global)) {
					t.Fatal("another site inherited an unrelated rate")
				}
			})
		}
	}
	base, old, next := apacheCCConfigFixture()
	off := false
	next.Policy.Sites = []core.WAFSitePolicy{{SiteID: apacheBodyConfigSiteA, Mode: "inherit", CCEnabled: &off}}
	out, err := transitionApacheBodySource(base, old, next)
	if err != nil || !strings.Contains(out, "YunzhanCCSite "+apacheBodyConfigSiteA+" off ") {
		t.Fatal("explicit site CC disable ignored", err)
	}
}

func TestApacheCCForeignOrModifiedSectionsAreNeverAdopted(t *testing.T) {
	base, old, next := apacheCCConfigFixture()
	out, err := transitionApacheBodySource(base, old, next)
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"wrong-rate":        strings.Replace(out, " block 20 60 ", " block 21 60 ", 1),
		"wrong-module":      strings.Replace(out, "mod_yunzhan_cc.so", "caller.so", 1),
		"missing-end":       strings.Replace(out, apacheCCSiteEnd, "", 1),
		"duplicate-site":    strings.Replace(out, apacheCCSiteBegin, apacheCCSiteBegin+apacheCCSiteBegin, 1),
		"outside-directive": out + "YunzhanCCSite " + apacheBodyConfigSiteA + " block 5 1 " + strings.Repeat("a", 64) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := transitionApacheBodySource(source, next, next); err == nil {
				t.Fatal("modified CC config adopted")
			}
		})
	}
	if _, err := transitionApacheBodySource(out, old, next); err == nil {
		t.Fatal("orphaned module treated as an empty installation")
	}
}
