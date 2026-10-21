package core

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAFApplyRequestActualAuthenticatedQueueBindsOriginalActorJobAndPayload(t *testing.T) {
	for _, app := range []string{"nginx-waf", "apache-waf"} {
		t.Run(app, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			cfg := DefaultWAFConfig()
			if app == "apache-waf" {
				cfg = DefaultApacheWAFConfig()
			}
			raw, _ := json.Marshal(map[string]any{"settings": WAFSettings(cfg)})
			r := httptest.NewRequest("POST", "/api/software/"+app+"/configure", strings.NewReader(string(raw)))
			r.Header.Set("Origin", a.Config.Origin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("Idempotency-Key", "original-actor-request")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			var out struct {
				Job string `json:"job_id"`
			}
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !ValidID(out.Job) {
				t.Fatal("actual actor-bound queue", w.Code, w.Body.String())
			}
			var actor, storedApp, key, digest, payload, state string
			if err := s.DB.QueryRow(`SELECT p.actor_id,p.app_id,p.idempotency_key,p.payload_sha256,j.payload,j.state FROM waf_apply_requests p JOIN runtime_jobs j ON j.id=p.job_id WHERE p.job_id=?`, out.Job).Scan(&actor, &storedApp, &key, &digest, &payload, &state); err != nil || actor != u.ID || storedApp != app || key != "original-actor-request" || digest != registryInstallDigest([]byte(payload)) || state != "queued" {
				t.Fatal("queue binding identity", err)
			}
			if _, err := wafApplyOriginalSettings(app, payload); err != nil {
				t.Fatal(err)
			}
			var audits int
			if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor=? AND action='software.configure' AND target=? AND result='queued'`, u.Username, app).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("original queued audit", audits, err)
			}
		})
	}
}

func TestWAFApplyRequestBindingFailureRollsBackOriginalJobAndRequestedAudit(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_owned_waf_binding BEFORE INSERT ON waf_apply_requests BEGIN SELECT RAISE(ABORT,'owned binding fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if job, err := s.queueWAFApplyRequest("nginx-waf", "configure", WAFSettings(DefaultWAFConfig()), "binding-failure", u); err == nil || job != "" {
		t.Fatal("failed binding queued job", job, err)
	}
	for _, table := range []string{"runtime_jobs", "waf_apply_requests", "audit_logs WHERE action='software.configure'"} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial bound transaction", table, count, err)
		}
	}
}

func TestWAFApplyRequestReplayCannotAdoptDifferentActorOrUnboundLegacyJob(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	settings := WAFSettings(DefaultWAFConfig())
	job, err := s.queueWAFApplyRequest("nginx-waf", "configure", settings, "bound-original", u)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := s.queueWAFApplyRequest("nginx-waf", "configure", settings, "bound-original", u); err != nil || replay != job {
		t.Fatal("original immutable replay", replay, err)
	}
	other := accessUser(t, s, "other-request-admin", "admin", []string{"runtimes", "security"})
	if replay, err := s.queueWAFApplyRequest("nginx-waf", "configure", settings, "bound-original", other); err == nil || replay != "" {
		t.Fatal("other actor adopted original", replay, err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.QueueSoftwareAction("nginx-waf", "configure", settings, "unbound-legacy", u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := s.queueWAFApplyRequest("nginx-waf", "configure", settings, "unbound-legacy", u); err == nil || replay != "" {
		t.Fatal("legacy unbound adopted by guessed key", replay, err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM waf_apply_requests WHERE job_id=?`, legacy).Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy binding backfilled", count, err)
	}
}

func TestWAFApplyRequestRevokedAccountCannotCommitOriginalBinding(t *testing.T) {
	for _, kind := range []string{"role", "menus", "deleted"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			statement := `UPDATE app_user_roles SET role='viewer' WHERE user_id=?`
			if kind == "menus" {
				statement = `UPDATE app_user_menus SET menu_ids='["runtimes"]' WHERE user_id=?`
			}
			if kind == "deleted" {
				statement = `DELETE FROM users WHERE id=?`
			}
			if _, err := s.DB.Exec(statement, u.ID); err != nil {
				t.Fatal(err)
			}
			if job, err := s.queueWAFApplyRequest("nginx-waf", "configure", WAFSettings(DefaultWAFConfig()), "revoked-before-bind", u); err == nil || job != "" {
				t.Fatal("revoked queue committed", job, err)
			}
			var count int
			if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&count); err != nil || count != 0 {
				t.Fatal("revoked partial job", count, err)
			}
		})
	}
}

func TestWAFApplyOriginalPayloadIsCanonicalClosedAndNotARecoveryWrite(t *testing.T) {
	for _, app := range []string{"nginx-waf", "apache-waf"} {
		cfg := DefaultWAFConfig()
		if app == "apache-waf" {
			cfg = DefaultApacheWAFConfig()
		}
		settings := WAFSettings(cfg)
		raw, _ := json.Marshal(map[string]any{"settings": settings, "version": ""})
		if _, err := wafApplyOriginalSettings(app, string(raw)); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{string(raw) + " ", `{"settings":{},"version":null}`, `{"settings":null,"version":""}`, strings.Replace(string(raw), `"version":""`, `"version":"","version":""`, 1), strings.Replace(string(raw), `"version":""`, `"version":"2.5.1"`, 1), strings.Replace(string(raw), `"version":""`, `"version":"","private":"/etc/shadow"`, 1), strings.Repeat("x", wafApplyPayloadMax+1)} {
			if _, err := wafApplyOriginalSettings(app, bad); err == nil {
				t.Fatal("malformed original payload accepted", bad[:min(len(bad), 100)])
			}
		}
	}
	t.Log("Original queue/binding and canonical JSON only; not native process, installation, recovery API or cold-start acceptance")
}

func TestWAFApplyVersionedOriginalRequiresExactSignedInstallContext(t *testing.T) {
	settings := WAFSettings(DefaultWAFConfig())
	raw, err := json.Marshal(map[string]any{"settings": settings, "version": "2.5.2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wafApplyOriginalSettingsForRequest("nginx-waf", "software_install", string(raw), "2.5.2"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct{ app, kind, signed string }{
		{"nginx-waf", "software_configure", "2.5.2"}, {"nginx-waf", "software_install", ""},
		{"nginx-waf", "software_install", "2.5.1"}, {"nginx-waf", "software_install", "2.5.3"},
		{"apache-waf", "software_install", "2.5.2"}, {"nginx-waf", "unknown", "2.5.2"},
	} {
		if _, err := wafApplyOriginalSettingsForRequest(value.app, value.kind, string(raw), value.signed); err == nil {
			t.Fatal("unbound version was authority", value)
		}
	}
	if _, err := wafApplyOriginalSettings("nginx-waf", string(raw)); err == nil {
		t.Fatal("legacy reader adopted a versioned original")
	}
}
