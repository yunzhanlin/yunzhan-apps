//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func apacheNativeRecordFixture(t *testing.T, version string, cfg core.WAFConfig) (*Service, []byte) {
	t.Helper()
	root := t.TempDir()
	security := filepath.Join(root, "security")
	for _, p := range []string{security, filepath.Join(security, "modules"), filepath.Join(security, "modules", "apache-waf")} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	s := New(Config{SystemRoot: root, SecurityDir: security, Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("pure installed-version planning invoked external command")
		return "", nil
	}})
	b, e := json.Marshal(map[string]any{"id": "apache-waf", "version": version, "settings": core.WAFSettings(cfg), "installed_at": "2026-10-23T00:00:00Z", "updated_at": "2026-10-23T00:00:00Z"})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(security, "modules", "apache-waf", "installed.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	return s, b
}

func TestApacheNativeLifecyclePrivateVersionAndRevisionAreNotRequestFlags(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 9
	s, original := apacheNativeRecordFixture(t, core.ApacheWAFVersion, cfg)
	if _, e := s.apacheNativeSettings(core.WAFSettings(cfg), false, false); e == nil {
		t.Fatal("metadata configure promoted native version")
	}
	if _, e := s.apacheNativeSettings(core.WAFSettings(cfg), true, false); e == nil {
		t.Fatal("reinstall overwrote metadata identity")
	}
	got, e := s.apacheNativeSettings(core.WAFSettings(cfg), false, true)
	if e != nil || got.Policy.Revision != 9 || got.Body != nil {
		t.Fatal("explicit version-only upgrade changed metadata settings", e)
	}
	if b, e := os.ReadFile(filepath.Join(s.moduleDir("apache-waf"), "installed.json")); e != nil || !reflect.DeepEqual(b, original) {
		t.Fatal("pure upgrade preparation rewrote original", e)
	}
	cfg.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{{SiteID: core.ID(), Policy: core.DefaultWAFBodyPolicy()}}}
	native, _ := apacheNativeRecordFixture(t, core.ApacheWAFNativeBodyVersion, cfg)
	if _, e := native.apacheNativeSettings(core.WAFSettings(cfg), true, false); e == nil {
		t.Fatal("native reinstall overwrote identity")
	}
	raw := core.WAFSettings(cfg)
	delete(raw, "body")
	merged, e := native.apacheNativeSettings(raw, false, false)
	if e != nil || merged.Body == nil || !reflect.DeepEqual(merged.Body, cfg.Body) {
		t.Fatal("metadata-only save erased native body policy", e)
	}
	stale := cfg
	stale.Policy.Revision--
	if _, e := native.apacheNativeSettings(core.WAFSettings(stale), false, false); e == nil {
		t.Fatal("stale revision accepted")
	}
	unrevisioned := core.WAFSettings(cfg)
	delete(unrevisioned, "policy")
	if _, e := native.apacheNativeSettings(unrevisioned, false, false); e == nil {
		t.Fatal("unrevisioned native activation accepted")
	}
	if _, e := native.apacheNativeSettings(map[string]any{"profile": "strict", "rate_per_second": 30}, false, false); e != nil {
		t.Fatal("legacy profile edit failed preserving native policy", e)
	}
	for _, version := range []string{"2.4.0-compat1", "2.5.0", "2.2.0"} {
		other, _ := apacheNativeRecordFixture(t, version, cfg)
		if _, e := other.apacheNativeSettings(nil, false, false); e == nil {
			t.Fatal("unknown or unmigrated record granted native write", version)
		}
	}
}

func TestApacheNativeCandidatePreservesOutsideAndRemovesOnlyExactBodyBlocks(t *testing.T) {
	module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
	old := core.DefaultApacheWAFConfig()
	old.Policy.Revision = 4
	source, rules, e := apacheMetadataSitePolicy(apacheMetadataSiteFixtureSource(), old, core.ApacheWAFVersion, module)
	if e != nil || rules == "" {
		t.Fatal(e)
	}
	next := old
	next.Policy.Revision++
	next.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{{SiteID: "0123456789abcdef0123456789abcdef", Policy: core.DefaultWAFBodyPolicy()}}}
	// Use the fixture's real bound ID, not a caller-provided foreign website.
	bindings, e := apacheWAFBindings(source)
	if e != nil || len(bindings) != 1 {
		t.Fatal(e)
	}
	for id := range bindings {
		next.Body.Sites[0].SiteID = id
	}
	prepared, nativeRules, e := apacheNativeCandidate(source, old, next, module)
	if e != nil || nativeRules == "" || !apacheBodyActive(next) {
		t.Fatal(e)
	}
	restored, _, e := apacheNativeCandidate(prepared, next, old, module)
	if e != nil || restored != source {
		t.Fatal("native enable/disable did not preserve exact outside bytes", e)
	}
	tampered := prepared + "\nSecRuleEngine Off\n"
	if _, _, e = apacheNativeCandidate(tampered, next, old, module); e == nil {
		t.Fatal("foreign directive adopted")
	}
	if _, _, e = apacheNativeCandidate(prepared, old, next, module); e == nil {
		t.Fatal("stale previous policy adopted")
	}
	if e = verifyApacheNativeBodyStorage(old); e != nil {
		t.Fatal("inactive policy requires no native storage", e)
	}
}
