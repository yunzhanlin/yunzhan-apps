package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestIntrusionRecoveryBodyIsClosedAndNeverUsesHardeningSchema(t *testing.T) {
	id, digest := ID(), Hash("intrusion original immutable source")
	valid := fmt.Sprintf(`{"settings":{"transaction_id":%q,"plan_sha256":%q}}`, id, digest)
	got, err := decodeIntrusionRecoveryBody([]byte(valid))
	if err != nil || len(got) != 2 || got["transaction_id"] != id || got["plan_sha256"] != digest {
		t.Fatal(got, err)
	}
	for name, raw := range map[string]string{
		"duplicate-envelope": strings.Replace(valid, `{"settings":`, `{"settings":{},"settings":`, 1),
		"duplicate-digest":   strings.Replace(valid, `"plan_sha256":`, `"plan_sha256":"other","plan_sha256":`, 1),
		"escaped-duplicate":  strings.Replace(valid, `"plan_sha256":`, `"plan_\u0073ha256":"other","plan_sha256":`, 1),
		"uppercase-key":      strings.Replace(valid, `"settings"`, `"Settings"`, 1),
		"uppercase-digest":   strings.Replace(valid, digest, strings.ToUpper(digest), 1),
		"short-digest":       strings.Replace(valid, digest, digest[:16], 1),
		"foreign-id":         strings.Replace(valid, id, "../foreign", 1),
		"hardening-digest":   strings.Replace(valid, "plan_sha256", "sha256", 1),
		"confirm":            strings.Replace(valid, `"transaction_id":`, `"confirm":"yes","transaction_id":`, 1),
		"script":             strings.Replace(valid, `"transaction_id":`, `"script":"nft flush ruleset","transaction_id":`, 1),
		"null":               `{"settings":null}`,
		"wrong-type":         strings.Replace(valid, fmt.Sprintf("%q", id), "42", 1),
		"trailing":           valid + `{}`,
		"oversized":          valid + strings.Repeat(" ", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeIntrusionRecoveryBody([]byte(raw)); err == nil {
				t.Fatal("ambiguous recovery authority accepted")
			}
		})
	}
}

func TestIntrusionRecoveryQueueBindsFullOriginalOnceAndAuditsOnce(t *testing.T) {
	s := testStore(t)
	settings := map[string]any{"transaction_id": ID(), "plan_sha256": Hash("actual private original")}
	job, err := s.QueueSoftwareAction("intrusion-prevention", "recover", settings, "intrusion-original-recovery", "admin")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.QueueSoftwareAction("intrusion-prevention", "recover", settings, "intrusion-original-recovery", "admin")
	if err != nil || job != again {
		t.Fatal("recovery forked", again, err)
	}
	var kind, raw string
	if err = s.DB.QueryRow("SELECT kind,payload FROM runtime_jobs WHERE id=?", job).Scan(&kind, &raw); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Settings map[string]any `json:"settings"`
		Version  string         `json:"version"`
	}
	if kind != "software_recover" || json.Unmarshal([]byte(raw), &payload) != nil || len(payload.Settings) != 2 || payload.Settings["transaction_id"] != settings["transaction_id"] || payload.Settings["plan_sha256"] != settings["plan_sha256"] || payload.Version != "" {
		t.Fatal("original source changed", kind, payload)
	}
	var audits int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='software.recover' AND target='intrusion-prevention'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("duplicate or missing original audit", audits, err)
	}
	changed := map[string]any{"transaction_id": settings["transaction_id"], "plan_sha256": Hash("different")}
	if _, err = s.QueueSoftwareAction("intrusion-prevention", "recover", changed, "intrusion-original-recovery", "admin"); err == nil {
		t.Fatal("different original reused key")
	}
	for _, target := range []string{"system-hardening", "nginx-waf", "files-sync"} {
		if _, err = s.QueueSoftwareAction(target, "recover", settings, "intrusion-foreign-"+target, "admin"); err == nil {
			t.Fatal("intrusion schema leaked", target)
		}
	}
}

func TestIntrusionVersionRequiresExactSignedInstallAndActualUpdate(t *testing.T) {
	s := testStore(t)
	for _, version := range []string{"", "1.0", "1.0.0", "1.1", "v1.1.0", "1.1.0-alias", "1.1.0", "1.1.1-alias", "1.1.2", "1.2.0", "01.1.0"} {
		if ValidateSoftwareUpdate("intrusion-prevention", version) == nil {
			t.Fatal("unimplemented or ambiguous update accepted", version)
		}
		if _, err := s.queueSoftwareAction("intrusion-prevention", "install", nil, version, "intrusion-version-"+version, "admin"); err == nil {
			t.Fatal("unsigned/legacy install promoted", version)
		}
	}
	if ValidateSoftwareUpdate("intrusion-prevention", IntrusionAppVersion) != nil {
		t.Fatal("fixed version rejected")
	}
	if _, err := s.queueSoftwareAction("intrusion-prevention", "install", nil, IntrusionAppVersion, "intrusion-signed-fixed-version", "admin"); err != nil {
		t.Fatal(err)
	}
}
