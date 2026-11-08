package core

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIntrusionRequestAuthenticatedHTTPBindsAccountAndRetrievesReadOnly(t *testing.T) {
	for _, action := range []string{"configure", "uninstall", "recover"} {
		t.Run(action, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			settings := map[string]any{"max_retry": 7, "find_time_minutes": 12, "ban_time_minutes": 120}
			if action == "uninstall" {
				settings = map[string]any{}
			}
			if action == "recover" {
				settings = map[string]any{"transaction_id": ID(), "plan_sha256": Hash("private original")}
			}
			key := ID()
			post := func(actor string) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(map[string]any{"actor_id": actor, "settings": settings})
				r := httptest.NewRequest("POST", "/api/software/intrusion-prevention/"+action, strings.NewReader(string(raw)))
				r.Header.Set("Origin", a.Config.Origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("Idempotency-Key", key)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			if w := post(ID()); w.Code != 400 {
				t.Fatal("stale other account accepted", w.Code, w.Body.String())
			}
			w := post(u.ID)
			var out struct {
				Job string `json:"job_id"`
			}
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !ValidID(out.Job) {
				t.Fatal(w.Code, w.Body.String())
			}
			if w := post(u.ID); w.Code != 202 || !strings.Contains(w.Body.String(), out.Job) {
				t.Fatal("original request forked", w.Code, w.Body.String())
			}
			var actor, digest, payload string
			if err := s.DB.QueryRow(`SELECT b.actor_id,b.payload_sha256,j.payload FROM intrusion_requests b JOIN runtime_jobs j ON j.id=b.job_id WHERE b.job_id=?`, out.Job).Scan(&actor, &digest, &payload); err != nil || actor != u.ID || digest != registryInstallDigest([]byte(payload)) || intrusionOriginalPayload("software_"+action, payload) != nil {
				t.Fatal("queue binding invalid", err)
			}
			r := httptest.NewRequest("GET", "/api/software/intrusion-prevention/requests", nil)
			r.AddCookie(cookie)
			w = httptest.NewRecorder()
			a.ServeHTTP(w, r)
			var page intrusionRequestPage
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &page) != nil || !page.ReadOnly || page.ActorID != u.ID || len(page.Entries) != 1 || page.Entries[0].ID != out.Job || page.Entries[0].RequestSHA256 != digest || page.Entries[0].State != "queued" {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), key) || strings.Contains(w.Body.String(), "settings") {
				t.Fatal("queue key or configuration exposed in directory")
			}
			var audits int
			if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action=? AND target='intrusion-prevention'`, "software."+action).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("missing/duplicate audit", audits, err)
			}
		})
	}
}

func TestIntrusionRequestBindingRejectsOtherActorAndUnboundLegacyWithoutAdoption(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	settings := map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
	key := ID()
	job, err := s.queueIntrusionRequest("configure", settings, key, u)
	if err != nil {
		t.Fatal(err)
	}
	other := accessUser(t, s, "other-intrusion-admin", "admin", []string{"runtimes", "security"})
	if _, err = s.queueIntrusionRequest("configure", settings, key, other); err == nil {
		t.Fatal("other actor adopted original")
	}
	page, err := s.readIntrusionRequests(other.ID, "")
	if err != nil || len(page.Entries) != 0 {
		t.Fatal("other account directory leaked", page, err)
	}
	if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	legacyKey := ID()
	legacy, err := s.QueueSoftwareAction("intrusion-prevention", "configure", settings, legacyKey, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.queueIntrusionRequest("configure", settings, legacyKey, u); err == nil {
		t.Fatal("unbound original backfilled")
	}
	var count int
	if err = s.DB.QueryRow(`SELECT count(*) FROM intrusion_requests WHERE job_id=?`, legacy).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if _, err = s.DB.Exec(`UPDATE intrusion_requests SET payload_sha256=? WHERE job_id=?`, Hash("foreign"), job); err != nil {
		t.Fatal(err)
	}
	if _, err = s.readIntrusionRequests(u.ID, ""); err == nil {
		t.Fatal("tampered immutable request adopted")
	}
}

func TestIntrusionRequestBindingFailureRollsBackJobAndAudit(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_owned_intrusion_binding BEFORE INSERT ON intrusion_requests BEGIN SELECT RAISE(ABORT,'owned binding fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if job, err := s.queueIntrusionRequest("uninstall", map[string]any{}, ID(), u); err == nil || job != "" {
		t.Fatal("partial queue committed", job, err)
	}
	for _, table := range []string{"runtime_jobs", "intrusion_requests", "audit_logs WHERE action='software.uninstall'"} {
		var count int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal(table, count, err)
		}
	}
}

func TestIntrusionRequestAccountRevocationAndStrictEnvelope(t *testing.T) {
	for _, kind := range []string{"role", "menus"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			statement := `UPDATE app_user_roles SET role='viewer' WHERE user_id=?`
			if kind == "menus" {
				statement = `UPDATE app_user_menus SET menu_ids='["runtimes"]' WHERE user_id=?`
			}
			if _, err := s.DB.Exec(statement, u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.queueIntrusionRequest("uninstall", nil, ID(), u); err == nil {
				t.Fatal("revoked actor queued")
			}
			if _, err := s.readIntrusionRequests(u.ID, ""); err == nil {
				t.Fatal("revoked actor read originals")
			}
		})
	}
	actor := ID()
	for _, raw := range []string{`{"settings":{}}`, `{"actor_id":"` + actor + `","settings":{},"settings":{}}`, `{"actor_id":"` + actor + `","settings":{"extra":1}}`, `{"Actor_id":"` + actor + `","settings":{}}`, `{"actor_id":"` + ID() + `","settings":{}}`, `{"actor_id":"` + actor + `","settings":null}`} {
		if _, err := decodeIntrusionActorBody([]byte(raw), actor, "uninstall"); err == nil {
			t.Fatal("ambiguous actor envelope accepted", raw)
		}
	}
}
