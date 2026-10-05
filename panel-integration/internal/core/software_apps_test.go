package core

import "testing"

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
