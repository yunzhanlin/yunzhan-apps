package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestHardeningRecoveryQueueBindsExactPlanAndOneOriginalAuditedJob(t *testing.T) {
	s := testStore(t)
	id := ID()
	settings := map[string]any{"transaction_id": id, "sha256": Hash("original immutable source"), "confirm": id}
	job, err := s.QueueSoftwareAction("system-hardening", "recover", settings, "hardening-source-recovery-one", "admin")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.QueueSoftwareAction("system-hardening", "recover", settings, "hardening-source-recovery-one", "admin")
	if err != nil || again != job {
		t.Fatal("recovery request forked", again, err)
	}
	var kind, payload string
	var count int
	if err = s.DB.QueryRow("select kind,payload from runtime_jobs where id=?", job).Scan(&kind, &payload); err != nil {
		t.Fatal(err)
	}
	if kind != "software_recover" {
		t.Fatal("wrong recovery job", kind)
	}
	var got struct {
		Settings map[string]any `json:"settings"`
		Version  string         `json:"version"`
	}
	if err = json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatal(err)
	}
	if got.Settings["transaction_id"] != id || got.Settings["sha256"] != settings["sha256"] || got.Version != "" {
		t.Fatal("original plan not bound", got)
	}
	if err = s.DB.QueryRow("select count(*)from audit_logs where action='software.recover' and target='system-hardening'").Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate/missing source audit", count, err)
	}
	changed := map[string]any{"transaction_id": id, "sha256": Hash("different"), "confirm": id}
	if _, err = s.QueueSoftwareAction("system-hardening", "recover", changed, "hardening-source-recovery-one", "admin"); err == nil {
		t.Fatal("original request identity accepted different source")
	}
	for _, app := range []string{"nginx-waf", "intrusion-prevention", "files-sync"} {
		if _, err = s.QueueSoftwareAction(app, "recover", settings, "foreign-recovery-"+app, "admin"); err == nil {
			t.Fatal("hardening protocol promoted to another app", app)
		}
	}
}

func TestHardeningRecoveryHTTPBodyRefusesDuplicateCaseFoldAndTrailingAuthority(t *testing.T) {
	id := ID()
	digest := Hash("original")
	valid := fmt.Sprintf(`{"settings":{"transaction_id":%q,"sha256":%q,"confirm":%q}}`, id, digest, id)
	if _, err := decodeHardeningRecoveryBody([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"duplicate-outer": strings.Replace(valid, `{"settings":`, `{"settings":{},"settings":`, 1), "duplicate-source": strings.Replace(valid, `"sha256":`, `"sha256":"foreign","sha256":`, 1), "case-fold": strings.Replace(valid, `"settings"`, `"Settings"`, 1), "extra-script": strings.Replace(valid, `"confirm":`, `"script":"not-permitted","confirm":`, 1), "trailing": valid + `{}`, "null": `{"settings":null}`} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeHardeningRecoveryBody([]byte(raw)); err == nil {
				t.Fatal("ambiguous HTTP authority accepted")
			}
		})
	}
}

func TestHardeningRecoverySchemaRejectsUnknownOrAmbiguousAuthority(t *testing.T) {
	id := ID()
	valid := map[string]any{"transaction_id": id, "sha256": Hash("original"), "confirm": id}
	if _, err := NormalizeHardeningRecovery(valid); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]map[string]any{"missing": {}, "wrong-confirm": {"transaction_id": id, "sha256": Hash("original"), "confirm": ID()}, "uppercase-digest": {"transaction_id": id, "sha256": strings.ToUpper(Hash("original")), "confirm": id}, "unknown-script": {"transaction_id": id, "sha256": Hash("original"), "confirm": id, "script": "not permitted"}, "bad-id": {"transaction_id": "../outside", "sha256": Hash("original"), "confirm": "../outside"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeHardeningRecovery(raw); err == nil {
				t.Fatal("ambiguous recovery authority accepted")
			}
		})
	}
}
