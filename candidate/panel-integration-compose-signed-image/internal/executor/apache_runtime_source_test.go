package executor

import (
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func TestApacheRuntimeSourcePreservesSiteRewritesPHPAndUnrelatedBytes(t *testing.T) {
	old, _ := runtimecatalog.Find(runtimecatalog.ApacheLegacyID)
	next, _ := runtimecatalog.Find(runtimecatalog.ApacheCurrentID)
	base, _, _ := apacheBodyConfigFixture()
	preserved := "  RewriteRule ^/old/(.*)$ /index.php?id=$1 [PT,L,QSA]\n  Options -Indexes -FollowSymLinks\n  SetHandler \"proxy:unix:/run/panel-php-stable/fpm.sock|fcgi://localhost/\"\n  # Keep an unrelated /opt/panel/runtimes/apache/2.4.68 literal\n"
	base += preserved
	result, err := apacheRuntimeSource(base, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, preserved) || !strings.Contains(result, "ServerRoot \""+next.Prefix()+"\"") || !strings.Contains(result, next.Prefix()+"/modules/mod_mpm_event.so") {
		t.Fatal("migration changed site semantics or left old standard module")
	}
	restored, err := apacheRuntimeSource(result, next, old)
	if err != nil || restored != base {
		t.Fatal("path-only reversal lost original bytes", err)
	}
	for _, bad := range []string{base + "LoadModule foreign_module /tmp/foreign.so\n", base + "LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so\n", base + "LoadModule proxy_module " + old.Prefix() + "/modules/mod_headers.so\n"} {
		if _, err := apacheRuntimeSource(bad, old, next); err == nil {
			t.Fatal("foreign loader admitted")
		}
	}
	_, previous, body := apacheBodyConfigFixture()
	enabled, err := transitionApacheBodySource(base, previous, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apacheRuntimeSource(enabled, old, next); err == nil {
		t.Fatal("native module ABI bypassed original-policy strip")
	}
}

func TestApacheRuntimePolicyPreservesFullRulesAndRequiresExplicitCompatibleEngine(t *testing.T) {
	_, previous, body := apacheBodyConfigFixture()
	body.Policy.Revision = 8
	body.ApacheCC = &core.ApacheWAFCCConfig{EngineJobID: apacheBodyConfigEngine}
	next, err := apacheRuntimePolicy(body, strings.Repeat("f", 32))
	if err != nil {
		t.Fatal(err)
	}
	if next.Policy.Revision != 9 || next.Body.EngineJobID != strings.Repeat("f", 32) || next.ApacheCC.EngineJobID != strings.Repeat("f", 32) {
		t.Fatal("generation/engine selection missing")
	}
	normalized := next
	normalized.Policy.Revision--
	normalized.Body.EngineJobID = body.Body.EngineJobID
	normalized.ApacheCC.EngineJobID = body.ApacheCC.EngineJobID
	if !reflect.DeepEqual(core.WAFSettings(normalized), core.WAFSettings(body)) {
		t.Fatal("runtime change altered existing policy")
	}
	if _, err := apacheRuntimePolicy(body, ""); err == nil {
		t.Fatal("native policy silently lost engine")
	}
	if _, err := apacheRuntimePolicy(previous, strings.Repeat("f", 32)); err == nil {
		t.Fatal("engine added to a policy without native capabilities")
	}
	if body.Body.EngineJobID != apacheBodyConfigEngine || body.Policy.Revision != 8 {
		t.Fatal("planning changed original policy object")
	}
}

func TestApacheRuntimeBuildRecordDoesNotRelabelHistoricalABI(t *testing.T) {
	old := apacheBodyFixtureRecord()
	altered := old
	altered.ApacheVersion = "2.4.71"
	if apacheBodyRecordContract(altered) == nil {
		t.Fatal("new version badge adopted old binary")
	}
	next := old
	next.ApacheVersion = "2.4.71"
	next.ApacheBinary = "/opt/panel/runtimes/apache/2.4.71/bin/httpd"
	if err := apacheBodyRecordContract(next); err != nil {
		t.Fatal("complete new-runtime authority not recognized", err)
	}
	paths := apacheBodyPathsForRelease(next.JobID, func() runtimecatalog.Release { r, _ := runtimecatalog.Find(runtimecatalog.ApacheCurrentID); return r }())
	if paths.Apache != "/opt/panel/runtimes/apache/2.4.71" {
		t.Fatal("new compiler used historical apxs")
	}
	retained := next
	retained.Engine = "2.9.15-yz4"
	retained.CompilerCollection = ""
	if apacheBodyRetainedRecordContract(retained) == nil {
		t.Fatal("historical retention contract expanded to new runtime")
	}
}
