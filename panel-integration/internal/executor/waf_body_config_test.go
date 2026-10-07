package executor

import (
	"strings"
	"testing"
)

func TestWAFBodyLoaderOwnedEnableDisable(t *testing.T) {
	id := strings.Repeat("a", 32)
	old := "# administrator header\nevents {}\nhttp {\n}\n"
	got, err := renderWAFBodyLoader(old, id, true)
	if err != nil || !strings.Contains(got, "load_module ") {
		t.Fatal(got, err)
	}
	again, err := renderWAFBodyLoader(got, id, true)
	if err != nil || again != got {
		t.Fatal("enable is not idempotent", err)
	}
	disabled, err := renderWAFBodyLoader(got, "", false)
	if err != nil || disabled != old {
		t.Fatal("disable changed original administrator text", err)
	}
	for _, bad := range []string{got + wafBodyLoaderEnd, strings.Replace(got, wafBodyLoaderEnd, "", 1), strings.Replace(got, "load_module ", "# custom\nload_module ", 1), got + got, "load_module /custom/modsecurity.so;\n" + old} {
		if _, err := renderWAFBodyLoader(bad, id, true); err == nil {
			t.Fatal("loader ownership conflict accepted")
		}
	}
}

func TestWAFBodySiteExplicitOptInAllServers(t *testing.T) {
	id := strings.Repeat("b", 32)
	old := "# managed by panel; site=" + id + "\nserver {\n  # HTTP\n}\nserver {\n  # HTTPS\n}\n"
	on, err := renderWAFBodySite(old, id, true)
	if err != nil || strings.Count(on, wafBodySiteBegin) != 2 {
		t.Fatal("not enabled on both managed ingress blocks", err)
	}
	again, err := renderWAFBodySite(on, id, true)
	if err != nil || again != on {
		t.Fatal("duplicate body rules", err)
	}
	off, err := renderWAFBodySite(on, id, false)
	if err != nil || off != old {
		t.Fatal("disable did not restore exact non-body bytes", err)
	}
	for _, bad := range []string{strings.Replace(on, "modsecurity on;", "modsecurity off;", 1), strings.Replace(on, id+".conf", strings.Repeat("a", 32)+".conf", 1), strings.Replace(old, id, "unmanaged", 1), strings.Replace(old, "site="+id, "site="+id+"; panel-waf-disabled", 1), "# managed by panel; site=" + id + "; disabled\n"} {
		if _, err := renderWAFBodySite(bad, id, true); err == nil {
			t.Fatal("edited/disabled/unmanaged body scope accepted")
		}
	}
	rules, err := wafBodyPolicyFile(defaultWAFBodyPolicy(), id, strings.Repeat("c", 32))
	if err != nil || !strings.HasPrefix(rules, "# managed by panel; native-waf-site="+id+";") || !strings.Contains(rules, "/var/cache/panel-waf-body/"+id) {
		t.Fatal("body ownership/policy paths", err)
	}
}
