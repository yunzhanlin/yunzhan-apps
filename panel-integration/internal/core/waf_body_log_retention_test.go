package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWAFBodyRetentionDefaultsAndExplicitDeletionSource(t *testing.T) {
	cfg := DefaultWAFConfig()
	data, _ := json.Marshal(cfg)
	if strings.Contains(string(data), "body_log_retention") {
		t.Fatal("default opted into deletion")
	}
	r := DefaultWAFBodyLogRetention()
	cfg.BodyLogRetention = &r
	if r.Enabled || r.ConfirmDelete || ValidateWAFBodyLogRotationSource(cfg) != nil {
		t.Fatal("invalid inert default")
	}
	r.Enabled = true
	if ValidateWAFBodyLogRetention(&r) == nil {
		t.Fatal("missing deletion acknowledgement accepted")
	}
	r.ConfirmDelete = true
	if ValidateWAFBodyLogRotationSource(cfg) == nil {
		t.Fatal("missing native source accepted")
	}
	cfg.Body = &WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []WAFBodySitePolicy{}}
	if ValidateWAFBodyLogRotationSource(cfg) != nil {
		t.Fatal("explicit valid source rejected")
	}
	for _, bad := range []WAFBodyLogRetentionConfig{{Days: 0, KeepLatest: 2}, {Days: 366, KeepLatest: 2}, {Days: 30, KeepLatest: 0}, {Days: 30, KeepLatest: 8}} {
		if ValidateWAFBodyLogRetention(&bad) == nil {
			t.Fatal("unbounded policy accepted", bad)
		}
	}
	for _, bad := range []any{nil, map[string]any{"enabled": false, "days": 30, "keep_latest": 2, "confirm_delete_completed_snapshots": false, "path": "/private"}} {
		raw := WAFSettings(cfg)
		raw["body_log_retention"] = bad
		if _, err := DecodeWAFConfig(raw); err == nil {
			t.Fatal("null or unknown retention input accepted")
		}
	}
}
