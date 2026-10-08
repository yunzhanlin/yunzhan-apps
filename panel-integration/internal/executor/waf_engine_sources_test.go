package executor

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestWAFNativeSourcesArePinnedAndIndependent(t *testing.T) {
	sources := wafEngineSources()
	if len(sources) != 3 {
		t.Fatal("missing native engine/connector/CRS source")
	}
	for _, version := range []string{"1.18.0", "1.24.0", "1.26.3", "1.30.4", "1.31.5"} {
		source, ok := wafNginxBuildSource(version)
		if !ok || !reviewedWAFEngineSource(source) {
			t.Fatal("missing reviewed build source", version)
		}
		sources = append(sources, source)
	}
	for _, version := range []string{"", "1.24.0 (Ubuntu)", "1.24.0;evil", "1.29.99"} {
		if _, ok := wafNginxBuildSource(version); ok {
			t.Fatal("accepted unknown build version", version)
		}
	}
	for _, source := range sources {
		u, err := url.Parse(source.URL)
		if err != nil || u.Scheme != "https" || (u.Host != "github.com" && u.Host != "nginx.org") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("unreviewed source: %+v", source)
		}
		b, err := hex.DecodeString(source.SHA256)
		if err != nil || len(b) != 32 || source.Verification == "" {
			t.Fatalf("missing fixed digest/provenance: %+v", source)
		}
	}
	sources[0].URL = "https://untrusted.invalid/replace"
	if wafEngineSources()[0].URL == sources[0].URL {
		t.Fatal("caller altered reviewed source allowlist")
	}
}

func TestWAFNativeAssetsAreCompleteAndVerified(t *testing.T) {
	for name := range wafEngineAssetPins() {
		b, err := verifiedWAFEngineAsset(name)
		if err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(name, "LICENSE") && !strings.Contains(string(b), "Redistribution") && !strings.Contains(string(b), "Grant of Copyright License") {
			t.Fatalf("%s lacks full license", name)
		}
	}
	for _, name := range []string{"../../private/key", "modsecurity-NOTICES.txt.extra", "", "modsecurity.cc"} {
		if _, err := verifiedWAFEngineAsset(name); err == nil {
			t.Fatal("accepted unreviewed asset", name)
		}
	}
}

func TestWAFBodyRenderingIsBoundedPrivateAndDeterministic(t *testing.T) {
	v := defaultWAFBodyPolicy()
	for _, pair := range []struct{ mode, engine string }{{"block", "On"}, {"observe", "DetectionOnly"}, {"off", "Off"}} {
		v.Mode = pair.mode
		out, err := renderWAFBodyRules(v, "/opt/panel/waf/engine/source", "/var/lib/panel/waf/tmp")
		if err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{"SecRuleEngine " + pair.engine, "SecAuditEngine Off", "SecResponseBodyAccess Off", "SecDebugLogLevel 0", "SecXmlExternalEntity Off", "SecUploadKeepFiles Off", "SecRequestBodyLimit 1048576", "SecRequestBodyNoFilesLimit 262144", "requestBodyProcessor=JSON", "requestBodyProcessor=XML", "SecRequestBodyJsonDepthLimit 64", "SecPcreMatchLimit 10000", "coreruleset-4.30.0/rules/*.conf"} {
			if !strings.Contains(out, expected) {
				t.Fatal("missing", expected)
			}
		}
		for _, forbidden := range []string{"SecAuditLogParts", "SecAuditLog ", "SecRuleScript", "SecRemoteRules", "%{MATCHED_VAR}", "%{REQUEST_BODY}", "%{REQUEST_HEADERS}", "ctl:requestBodyAccess=Off"} {
			if strings.Contains(out, forbidden) {
				t.Fatal("unsafe rendering", forbidden)
			}
		}
		again, _ := renderWAFBodyRules(v, "/opt/panel/waf/engine/source", "/var/lib/panel/waf/tmp")
		if out != again {
			t.Fatal("not deterministic")
		}
	}
}

func TestWAFBodyRejectsPolicyAndPathInjection(t *testing.T) {
	v := defaultWAFBodyPolicy()
	for _, mutate := range []func(*wafBodyPolicy){func(v *wafBodyPolicy) { v.Mode = "On\nSecAuditEngine On" }, func(v *wafBodyPolicy) { v.Paranoia = 5 }, func(v *wafBodyPolicy) { v.Threshold = 4 }, func(v *wafBodyPolicy) { v.BodyLimitKiB = 8193 }, func(v *wafBodyPolicy) { v.NonFileLimitKiB = 1025 }, func(v *wafBodyPolicy) { v.NonFileLimitKiB = 0 }, func(v *wafBodyPolicy) { v.JSONDepth = 129 }, func(v *wafBodyPolicy) { v.ArgumentLimit = 1001 }} {
		bad := v
		mutate(&bad)
		if _, err := renderWAFBodyRules(bad, "/opt/panel/waf/source", "/var/lib/panel/waf/tmp"); err == nil {
			t.Fatal("accepted invalid policy", bad)
		}
	}
	for _, path := range []string{"/", "relative", "/opt/panel/../secret", "/opt//panel", "/opt/panel/", "/opt/panel\nSecRuleEngine Off", "/opt/panel;", "/opt/\"evil", "/opt/$variable", "/opt/*"} {
		if _, err := renderWAFBodyRules(v, path, "/var/lib/panel/waf/tmp"); err == nil {
			t.Fatal("accepted injected source", path)
		}
		if _, err := renderWAFBodyRules(v, "/opt/panel/waf/source", path); err == nil {
			t.Fatal("accepted injected tmp", path)
		}
	}
}
