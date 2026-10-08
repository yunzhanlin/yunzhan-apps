package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWAFBodyLogRotationExplicitBoundedAndNonDestructive(t *testing.T) {
	cfg := DefaultWAFConfig()
	b, _ := json.Marshal(cfg)
	if strings.Contains(string(b), "body_log_rotation") {
		t.Fatal("default silently opted into rotation")
	}
	rotation := DefaultWAFBodyLogRotation()
	cfg.BodyLogRotation = &rotation
	if rotation.Enabled || ValidateWAFBodyLogRotationSource(cfg) != nil {
		t.Fatal("disabled draft should need no engine")
	}
	rotation.Enabled = true
	if ValidateWAFBodyLogRotationSource(cfg) == nil {
		t.Fatal("enabled without an explicit engine")
	}
	cfg.Body = &WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []WAFBodySitePolicy{}}
	if ValidateWAFBodyLogRotationSource(cfg) != nil {
		t.Fatal("explicit paused engine source rejected")
	}
	for _, v := range []WAFBodyLogRotationConfig{{true, 0, 60}, {true, 29, 60}, {true, 16, 9}, {true, 16, 1441}} {
		if ValidateWAFBodyLogRotation(&v) == nil {
			t.Fatal("unbounded policy accepted", v)
		}
	}
	for _, raw := range []string{`{"enabled":true,"rotate_mib":16,"max_age_minutes":60,"prune":true}`, `null`} {
		settings := WAFSettings(cfg)
		var v any
		_ = json.Unmarshal([]byte(raw), &v)
		settings["body_log_rotation"] = v
		if _, err := DecodeWAFConfig(settings); err == nil {
			t.Fatal("unknown/null rotation fields accepted")
		}
	}
}
