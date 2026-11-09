package core

import (
	"strings"
	"testing"
)

func apacheCCSettingsFixture() map[string]any {
	cfg := DefaultApacheWAFConfig()
	cfg.Policy.CCEnabled = true
	cfg.ApacheCC = &ApacheWAFCCConfig{EngineJobID: strings.Repeat("a", 32)}
	return WAFSettings(cfg)
}

func TestApacheCCVersionAndNginxAuthorityStaySeparate(t *testing.T) {
	raw := apacheCCSettingsFixture()
	if _, err := DecodeApacheWAFNativeCCConfig(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeApacheWAFVersionConfig(raw, ApacheWAFNativeCCVersion); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{ApacheWAFVersion, ApacheWAFNativeBodyVersion, "2.5.0-alias", "2.6.0"} {
		if _, err := DecodeApacheWAFVersionConfig(raw, version); err == nil {
			t.Fatal("older/unknown version acquired CC", version)
		}
	}
	if _, err := DecodeWAFConfig(raw); err == nil {
		t.Fatal("Nginx accepted Apache module authority")
	}
	for _, version := range []string{ApacheWAFVersion, ApacheWAFNativeBodyVersion, ApacheWAFNativeCCVersion} {
		foreign := WAFSettings(DefaultApacheWAFConfig())
		foreign["country"] = map[string]any{"enabled": false}
		if _, err := DecodeApacheWAFVersionConfig(foreign, version); err == nil {
			t.Fatal("Apache silently accepted Nginx-only country policy", version)
		}
	}
	for _, v := range []string{ApacheWAFNativeBodyVersion, ApacheWAFNativeCCVersion} {
		if err := ValidateSoftwareInstallVersion("apache-waf", v); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"2.5.0-alias", "2.6.0"} {
		if ValidateSoftwareInstallVersion("apache-waf", v) == nil {
			t.Fatal("unknown signed install version accepted", v)
		}
	}
}

func TestApacheCCRequiresExactExplicitEngineReference(t *testing.T) {
	for _, value := range []any{nil, "arbitrary", map[string]any{}, map[string]any{"engine_job_id": "../other"}, map[string]any{"engine_job_id": strings.Repeat("a", 32), "path": "/tmp/caller.so"}} {
		raw := apacheCCSettingsFixture()
		raw["apache_cc"] = value
		if _, err := DecodeApacheWAFNativeCCConfig(raw); err == nil {
			t.Fatalf("invalid reference accepted: %#v", value)
		}
	}
	raw := apacheCCSettingsFixture()
	delete(raw, "apache_cc")
	if _, err := DecodeApacheWAFNativeCCConfig(raw); err == nil {
		t.Fatal("CC policy accepted without an explicit local engine")
	}
	raw = apacheCCSettingsFixture()
	delete(raw, "policy")
	if _, err := DecodeApacheWAFNativeCCConfig(raw); err == nil {
		t.Fatal("native CC reference accepted without full revision policy")
	}
	if _, err := DecodeApacheWAFNativeCCConfig(WAFSettings(DefaultApacheWAFConfig())); err != nil {
		t.Fatal("unchanged old body-only settings cannot be preserved", err)
	}
}
