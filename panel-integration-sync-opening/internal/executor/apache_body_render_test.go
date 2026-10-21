package executor

import (
	"strings"
	"testing"
)

func TestApacheBodyRendererClosedModesLimitsPrivacyAndV2Identity(t *testing.T) {
	for _, mode := range []string{"block", "observe", "off"} {
		p := defaultWAFBodyPolicy()
		p.Mode = mode
		b, err := renderApacheBodyRules(p, "/private/resources", "/private/tmp")
		if err != nil {
			t.Fatal(err)
		}
		engine := map[string]string{"block": "On", "observe": "DetectionOnly", "off": "Off"}[mode]
		limitAction := "Reject"
		if mode == "observe" {
			limitAction = "ProcessPartial"
		}
		for _, required := range []string{
			"SecRuleEngine " + engine + "\n", apacheBodyEngineVersion, apacheBodyYAJLVersion,
			"SecRequestBodyLimitAction " + limitAction + "\n",
			"SecAuditEngine Off\n", "SecResponseBodyAccess Off\n", "SecDebugLogLevel 0\n", "SecXmlExternalEntity Off\n",
			"SecUploadKeepFiles Off\n", "SecRequestBodyLimit 1048576\n", "SecRequestBodyNoFilesLimit 262144\n",
			"SecRequestBodyJsonDepthLimit 64\n", "SecArgumentsLimit 256\n", "requestBodyProcessor=JSON", "requestBodyProcessor=XML",
			"coreruleset-4.30.0/rules/*.conf",
		} {
			if !strings.Contains(b, required) {
				t.Fatal("missing fixed v2 body/privacy directive", required)
			}
		}
		for _, forbidden := range []string{"3.0.17", "connector", "SecRemoteRules", "SecAuditLogParts", "logdata:", "exec:", "SecResponseBodyAccess On", "SecStatusEngine", "SecPcreMatchLimit", "SecUnicodeMapFile"} {
			if strings.Contains(b, forbidden) {
				t.Fatal("v3 identity or unsafe side effect", forbidden)
			}
		}
		nginx, _ := renderWAFBodyRules(p, "/private/resources", "/private/tmp")
		if strings.Contains(nginx, "SecStatusEngine") || !strings.Contains(nginx, "modsecurity-v3.0.17/unicode.mapping") {
			t.Fatal("Apache renderer modified Nginx's existing contract")
		}
		bound, err := renderApacheBodySiteRules(p, "/private/resources", "/private/tmp", "0123456789abcdef0123456789abcdef")
		if err != nil || bound != "SecAction \"id:128000,phase:1,t:none,pass,nolog,setenv:PANEL_AW_SITE=0123456789abcdef0123456789abcdef\"\n"+b {
			t.Fatal("phase 1 must have exact managed identity before any alert", err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("A", 32), strings.Repeat("g", 32), "abc\nInclude /etc/passwd"} {
		if _, err := renderApacheBodySiteRules(defaultWAFBodyPolicy(), "/private/resources", "/private/tmp", bad); err == nil {
			t.Fatal("caller-selected/injected site identity accepted")
		}
	}
	global, err := renderApacheBodyGlobalRules("/private/resources")
	if err != nil || global != "SecStatusEngine Off\nSecPcreMatchLimit 10000\nSecPcreMatchLimitRecursion 10000\nSecUnicodeMapFile /private/resources/modsecurity-v2.9.15/unicode.mapping 20127\n" {
		t.Fatal("global-only v2 configuration changed", global, err)
	}
	p := defaultWAFBodyPolicy()
	for _, bad := range []string{"/private\nInclude /etc/passwd", "/private;id", "/private/../other", "/"} {
		if _, err := renderApacheBodyGlobalRules(bad); err == nil {
			t.Fatal("global resource path injection accepted")
		}
		if _, err := renderApacheBodyRules(p, bad, "/private/tmp"); err == nil {
			t.Fatal("source resource path injection accepted")
		}
		if _, err := renderApacheBodyRules(p, "/private/resources", bad); err == nil {
			t.Fatal("temporary path injection accepted")
		}
	}
	p.Mode = "unknown"
	if _, err := renderApacheBodyRules(p, "/private/resources", "/private/tmp"); err == nil {
		t.Fatal("unknown policy accepted")
	}
}
