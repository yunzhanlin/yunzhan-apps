package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func maintenanceTestInput(id, command string) PlatformMaintenanceInput {
	in := PlatformMaintenanceInput{RequestID: id, Command: command, ExpectedPlanSHA: strings.Repeat("e", 64)}
	if command == "nginx-reload" {
		in.Confirm = "RELOAD NGINX " + in.ExpectedPlanSHA
	}
	return in
}
func TestPlatformMaintenanceClosedProtocolAndNoFalseServiceHealth(t *testing.T) {
	for _, command := range PlatformMaintenanceCommands() {
		in := maintenanceTestInput(ID(), command)
		raw, _ := json.Marshal(in)
		got, e := DecodePlatformMaintenanceInput(raw)
		if e != nil || got != in {
			t.Fatal(e)
		}
		for _, bad := range []string{string(raw) + "{}", `{"request_id":"` + in.RequestID + `",` + string(raw[1:]), strings.Replace(string(raw), `"command"`, `"shell"`, 1), strings.Replace(string(raw), command, "stop", 1)} {
			if _, e := DecodePlatformMaintenanceInput([]byte(bad)); e == nil {
				t.Fatal("unsafe command accepted")
			}
		}
		req := PlatformMaintenanceNativeRequest{Format: 1, ActorID: ID(), GrantID: strings.Repeat("a", 64), Input: in}
		row := PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: PlatformMaintenanceRequestSHA(req), State: "completed", Outcome: "config_valid"}
		if command == "nginx-reload" {
			row.Outcome = "reload_signal_submitted"
		}
		wire, _ := json.Marshal(row)
		if _, e := DecodePlatformMaintenanceRecord(wire, req); e != nil {
			t.Fatal(e)
		}
		row.Outcome = "all_websites_healthy"
		wire, _ = json.Marshal(row)
		if _, e := DecodePlatformMaintenanceRecord(wire, req); e == nil {
			t.Fatal("false service health accepted")
		}
	}
}
func TestPlatformMaintenanceStoredLifetimeCorruptionNeverAuthenticatesOrDispatches(t *testing.T) {
	a, actor := maintenanceIdentityFixture(t)
	issued, e := a.Store.issuePlatformMaintenanceGrant(context.Background(), actor.ID, PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}, maintenanceTestInstallationID)
	if e != nil {
		t.Fatal(e)
	}
	out := issued.(map[string]any)
	id, token := out["grant_id"].(string), out["token"].(string)
	original, e := a.Store.platformMaintenanceGrant(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, row := range []struct {
		created string
		expires int64
	}{
		{"not-a-time", now.Unix() + 3600},
		{now.Format(time.RFC3339), now.Unix() + 86401},
		{now.Format(time.RFC3339), now.Unix() + 299},
		{now.Add(10 * time.Minute).Format(time.RFC3339), now.Unix() + 4200},
	} {
		if _, e := a.Store.DB.Exec("UPDATE platform_maintenance_grants SET created_at=?,expires_at=? WHERE token_hash=?", row.created, row.expires, id); e != nil {
			t.Fatal(e)
		}
		if _, e := a.Store.platformMaintenanceGrant(context.Background(), id); e == nil {
			t.Fatal("corrupt grant inventory accepted")
		}
		r := httptest.NewRequest("GET", "/api/platform-maintenance/plan", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if _, e := a.platformMaintenanceBearer(r); e == nil {
			t.Fatal("corrupt grant authenticated")
		}
		if _, _, _, e := a.Store.beginPlatformMaintenance(context.Background(), original, maintenanceTestInput(ID(), "nginx-check")); e == nil {
			t.Fatal("corrupt lifetime passed pre-dispatch reread")
		}
	}
	var count int
	if e := a.Store.DB.QueryRow("SELECT count(*) FROM platform_maintenance_operations").Scan(&count); e != nil || count != 0 {
		t.Fatal("invalid grant created operations", count, e)
	}
}
func TestPlatformMaintenanceGrantIsolationExpirationRoleAndAuditRollback(t *testing.T) {
	a, actor := maintenanceIdentityFixture(t)
	input := PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}
	issued, e := a.Store.issuePlatformMaintenanceGrant(context.Background(), actor.ID, input, maintenanceTestInstallationID)
	if e != nil {
		t.Fatal(e)
	}
	out := issued.(map[string]any)
	token := out["token"].(string)
	id := out["grant_id"].(string)
	if id != Hash(token) || token == id {
		t.Fatal("secret identity invalid")
	}
	r := httptest.NewRequest("GET", "/api/platform-maintenance/plan", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, e = a.platformMaintenanceBearer(r); e != nil {
		t.Fatal(e)
	}
	for _, bearer := range []string{strings.Repeat("1", 64), id, "bad"} {
		r.Header.Set("Authorization", "Bearer "+bearer)
		if _, e = a.platformMaintenanceBearer(r); e == nil {
			t.Fatal("readonly token/digest authenticated maintenance")
		}
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cookie", "session=opaque")
	if _, e = a.platformMaintenanceBearer(r); e == nil {
		t.Fatal("session bearer mixing accepted")
	}
	r.Header.Del("Cookie")
	if _, e = a.Store.DB.Exec("UPDATE platform_maintenance_grants SET expires_at=? WHERE token_hash=?", time.Now().Unix()-1, id); e != nil {
		t.Fatal(e)
	}
	if _, e = a.platformMaintenanceBearer(r); e == nil {
		t.Fatal("expired grant authenticated")
	}
	if _, e = a.Store.DB.Exec("UPDATE platform_maintenance_grants SET expires_at=?,revoked=1 WHERE token_hash=?", time.Now().Unix()+60, id); e != nil {
		t.Fatal(e)
	}
	if _, e = a.platformMaintenanceBearer(r); e == nil {
		t.Fatal("revoked grant authenticated")
	}
	before := platformTables(t, a.Store)
	if _, e = a.Store.DB.Exec(`CREATE TRIGGER maintenance_deny_audit BEFORE INSERT ON audit_logs WHEN NEW.action='platform.maintenance.grant.issue' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`); e != nil {
		t.Fatal(e)
	}
	var count int
	a.Store.DB.QueryRow("SELECT count(*) FROM platform_maintenance_grants").Scan(&count)
	if _, e = a.Store.issuePlatformMaintenanceGrant(context.Background(), actor.ID, input, maintenanceTestInstallationID); e == nil {
		t.Fatal("grant escaped failed audit")
	}
	var after int
	a.Store.DB.QueryRow("SELECT count(*) FROM platform_maintenance_grants").Scan(&after)
	if after != count || !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("failed issue modified legacy hosts/tokens/audit")
	}
}
func TestPlatformMaintenanceOriginalCommandBindingNoRetryAndReconciliation(t *testing.T) {
	a, actor := maintenanceIdentityFixture(t)
	issued, e := a.Store.issuePlatformMaintenanceGrant(context.Background(), actor.ID, PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}, maintenanceTestInstallationID)
	if e != nil {
		t.Fatal(e)
	}
	id := issued.(map[string]any)["grant_id"].(string)
	grant, e := a.Store.platformMaintenanceGrant(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	in := maintenanceTestInput(ID(), "nginx-reload")
	req, state, _, e := a.Store.beginPlatformMaintenance(context.Background(), grant, in)
	if e != nil || state != "new" {
		t.Fatal(state, e)
	}
	_, state, _, e = a.Store.beginPlatformMaintenance(context.Background(), grant, in)
	if e != nil || state != "dispatched" {
		t.Fatal("same ID republished", state, e)
	}
	changed := in
	changed.ExpectedPlanSHA = strings.Repeat("c", 64)
	changed.Confirm = "RELOAD NGINX " + changed.ExpectedPlanSHA
	if _, _, _, e = a.Store.beginPlatformMaintenance(context.Background(), grant, changed); e == nil {
		t.Fatal("same ID rebound")
	}
	row := PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: PlatformMaintenanceRequestSHA(req), State: "completed", Outcome: "reload_signal_submitted"}
	wire, _ := json.Marshal(row)
	if _, e = a.Store.DB.Exec("UPDATE platform_maintenance_operations SET state='needs_attention' WHERE request_id=?", in.RequestID); e != nil {
		t.Fatal(e)
	}
	bad := row
	bad.Request.ActorID = ID()
	bad.RequestSHA = PlatformMaintenanceRequestSHA(bad.Request)
	v, _ := json.Marshal(bad)
	if a.Store.finishPlatformMaintenance(context.Background(), req, v) == nil {
		t.Fatal("foreign actor resolved original")
	}
	if e = a.Store.finishPlatformMaintenance(context.Background(), req, wire); e != nil {
		t.Fatal(e)
	}
	if e = a.Store.finishPlatformMaintenance(context.Background(), req, wire); e != nil {
		t.Fatal("identical original replay rejected", e)
	}
	bad = row
	bad.State = "failed"
	bad.Outcome = "command_failed"
	v, _ = json.Marshal(bad)
	if a.Store.finishPlatformMaintenance(context.Background(), req, v) == nil {
		t.Fatal("original terminal overwritten")
	}
	var n int
	a.Store.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='platform.maintenance.command.complete' AND target=?", in.RequestID).Scan(&n)
	if n != 1 {
		t.Fatal("completion duplicated", n)
	}
}
func TestPlatformMaintenanceLimitedAdministratorCannotGrantHostReload(t *testing.T) {
	s := testStore(t)
	limited := accessUser(t, s, "maint-limited", "admin", []string{"system-tools"})
	in := PlatformMaintenanceGrantInput{Commands: []string{"nginx-reload"}, Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}
	if _, e := s.issuePlatformMaintenanceGrant(context.Background(), limited.ID, in, maintenanceTestInstallationID); e == nil {
		t.Fatal("limited admin granted host reload")
	}
	in.Commands = []string{"nginx-check"}
	if _, e := s.issuePlatformMaintenanceGrant(context.Background(), limited.ID, in, maintenanceTestInstallationID); e != nil {
		t.Fatal("allowed config check grant rejected", e)
	}
}
func TestPlatformMaintenancePeerStrictTLSClosedPlansAndNoMutationRetry(t *testing.T) {
	token := strings.Repeat("b", 64)
	request := maintenanceTestInput(ID(), "nginx-check")
	req := PlatformMaintenanceNativeRequest{Format: 1, ActorID: ID(), GrantID: Hash(token), Input: request}
	row := PlatformMaintenanceRecord{Format: 1, Request: req, RequestSHA: PlatformMaintenanceRequestSHA(req), State: "completed", Outcome: "config_valid"}
	wire, _ := json.Marshal(row)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Cookie") != "" {
			t.Fatal("secret scope/cookie incorrect")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(wire)
	}))
	defer server.Close()
	client := platformMaintenanceClient()
	defer client.CloseIdleConnections()
	if _, _, e := platformMaintenancePeerCall(context.Background(), client, server.URL, token, "POST", "/api/platform-maintenance/commands", []byte("{}")); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if calls != 0 {
		t.Fatal("invalid certificate reached handler")
	}
	trusted := server.Client()
	trusted.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	got, status, e := platformMaintenancePeerCall(context.Background(), trusted, server.URL, token, "POST", "/api/platform-maintenance/commands", []byte("{}"))
	if e != nil || status != 200 || !bytes.Equal(got, wire) || calls != 1 {
		t.Fatal(status, e, calls)
	}
	for _, bad := range []string{"http://localhost", "https://u:p@host/", "https://host/?token=secret", "https://host/#x", "https://host/a/../b"} {
		if validatePlatformMaintenancePeer(bad, token) == nil {
			t.Fatal("unsafe peer accepted", bad)
		}
	}
	counter := 0
	broken := &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) { counter++; return nil, errors.New("synthetic EOF") })}
	if _, _, e = platformMaintenancePeerCall(context.Background(), broken, "https://owned.invalid", token, "POST", "/api/platform-maintenance/commands", nil); e == nil || counter != 1 {
		t.Fatal("mutation retried", e, counter)
	}
	plan := PlatformMaintenanceRemotePlan{Plan: PlatformMaintenancePlan{Format: 1, SHA: request.ExpectedPlanSHA, Commands: PlatformMaintenanceCommands()}, GrantID: Hash(token), ActorID: req.ActorID, AllowedCommands: []string{"nginx-check"}, Expires: time.Now().Unix() + 60}
	raw, _ := json.Marshal(plan)
	if _, e := decodePlatformMaintenanceRemotePlan(raw, token); e != nil {
		t.Fatal(e)
	}
	if _, e := decodePlatformMaintenanceRemotePlan(append(raw, []byte("{}")...), token); e == nil {
		t.Fatal("trailing protocol accepted")
	}
}
