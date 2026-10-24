package core

import (
	"encoding/json"
	"testing"
)

func TestSoftwareActionQueueValidationAndIdempotency(t *testing.T) {
	s := testStore(t)
	settings := map[string]any{"profile": "balanced", "rate_per_second": float64(20)}
	job, err := s.QueueSoftwareAction("nginx-waf", "install", settings, "software-install-one", "admin")
	if err != nil || job == "" {
		t.Fatal(job, err)
	}
	repeated, err := s.QueueSoftwareAction("nginx-waf", "install", settings, "software-install-one", "admin")
	if err != nil || repeated != job {
		t.Fatal("idempotent retry changed job", repeated, err)
	}
	if _, err = s.QueueSoftwareAction("nginx-waf", "configure", settings, "software-install-one", "admin"); err == nil {
		t.Fatal("idempotency key accepted another action")
	}
	if _, err = s.QueueSoftwareAction("unknown", "install", settings, "unknown-app", "admin"); err == nil {
		t.Fatal("unknown software accepted")
	}
	if _, err = s.QueueSoftwareAction("nginx-waf", "install", map[string]any{"profile": "strict", "rate_per_second": float64(2)}, "bad-rate", "admin"); err == nil {
		t.Fatal("unsafe WAF rate accepted")
	}
	var jobs, audits int
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE id=? AND target_id='nginx-waf' AND kind='software_install' AND state='queued'`, job).Scan(&jobs)
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='software.install' AND target='nginx-waf'`).Scan(&audits)
	if jobs != 1 || audits != 1 {
		t.Fatal("software job or audit missing", jobs, audits)
	}
}

func TestSoftwareSettingsAreClosedSchemas(t *testing.T) {
	tests := []struct {
		id       string
		settings map[string]any
	}{
		{"nginx-waf", map[string]any{"profile": "balanced", "rate_per_second": float64(20)}},
		{"system-hardening", map[string]any{"profile": "baseline"}},
		{"intrusion-prevention", map[string]any{"max_retry": float64(5), "find_time_minutes": float64(10), "ban_time_minutes": float64(60)}},
	}
	for _, test := range tests {
		if _, err := normalizeSoftwareSettings(test.id, test.settings); err != nil {
			t.Fatalf("%s: %v", test.id, err)
		}
	}
	if _, err := normalizeSoftwareSettings("system-hardening", map[string]any{"profile": "dangerous"}); err == nil {
		t.Fatal("unknown hardening profile accepted")
	}
}

func TestWAFLegacySettingsNeverSilentlyDiscardAdvancedPolicyFields(t *testing.T) {
	cfg := DefaultWAFConfig()
	cfg.TrustedProxy = &WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"127.0.0.1/32"}, AcknowledgeHeaderControl: true}
	rotation, retention := DefaultWAFBodyLogRotation(), DefaultWAFBodyLogRetention()
	cfg.BodyLogRotation, cfg.BodyLogRetention = &rotation, &retention
	complete := WAFSettings(cfg)
	for _, field := range []string{"trusted_proxy", "body_log_rotation", "body_log_retention"} {
		t.Run(field, func(t *testing.T) {
			partial := map[string]any{"profile": "balanced", "rate_per_second": 20, field: complete[field]}
			if normalized, err := normalizeSoftwareSettings("nginx-waf", partial); err == nil {
				t.Fatalf("advanced intent silently accepted/discarded without policy: %s %#v", field, normalized)
			}
			s := testStore(t)
			if _, err := s.QueueSoftwareAction("nginx-waf", "configure", partial, "partial-advanced-"+field, "admin"); err == nil {
				t.Fatal("partial advanced policy queued")
			}
			var jobs, audits int
			_ = s.DB.QueryRow("SELECT count(*) FROM runtime_jobs").Scan(&jobs)
			_ = s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='software.configure'").Scan(&audits)
			if jobs != 0 || audits != 0 {
				t.Fatal("rejected partial intent created jobs or success audit", jobs, audits)
			}
		})
	}
	normalized, err := normalizeSoftwareSettings("nginx-waf", complete)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"trusted_proxy", "body_log_rotation", "body_log_retention", "policy"} {
		before, _ := json.Marshal(complete[field])
		after, _ := json.Marshal(normalized[field])
		if string(before) != string(after) {
			t.Fatal("complete advanced policy changed", field)
		}
	}
}

func TestStatisticsInstallQueueBindsSelectedVersionWithoutImplicitUpgrade(t *testing.T) {
	s := testStore(t)
	job, err := s.queueSoftwareAction("website-statistics-v2", "install", nil, "2.4.0", "selected-statistics", "admin")
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err = s.DB.QueryRow("SELECT payload FROM runtime_jobs WHERE id=?", job).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version string `json:"version"`
	}
	if json.Unmarshal([]byte(raw), &payload) != nil || payload.Version != "2.4.0" {
		t.Fatal("selected package version was not retained", raw)
	}
	if _, err = s.queueSoftwareAction("website-statistics-v2", "install", nil, "2.7.0", "unimplemented-statistics", "admin"); err == nil {
		t.Fatal("unimplemented schema opt-in accepted")
	}
	// Complete the old queue-only fixture before requesting another action;
	// the real same-target pending-job exclusion remains intact.
	if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job); err != nil {
		t.Fatal(err)
	}
	job, err = s.queueSoftwareAction("website-statistics-v2", "install", nil, "2.5.0", "implemented-statistics", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow("SELECT payload FROM runtime_jobs WHERE id=?", job).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal([]byte(raw), &payload) != nil || payload.Version != "2.5.0" {
		t.Fatal("actual selected identity version was lost", raw)
	}
}
