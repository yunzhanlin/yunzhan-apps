package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const maintenanceTestInstallationID = "dddddddddddddddddddddddddddddddd"

func TestPlatformMaintenanceRevocationCannotCrossHigherAdministratorScope(t *testing.T) {
	s := testStore(t)
	full := accessUser(t, s, "maintenance-revoke-full", "admin", nil)
	limited := accessUser(t, s, "maintenance-revoke-limited", "admin", []string{"system-tools"})
	viewer := accessUser(t, s, "maintenance-revoke-viewer", "viewer", nil)
	ctx := context.Background()
	for _, row := range []struct {
		actor, owner string
		allowed      bool
	}{{full.ID, limited.ID, true}, {limited.ID, limited.ID, true}, {limited.ID, full.ID, false}, {viewer.ID, viewer.ID, false}, {full.ID, "invalid", false}} {
		if platformMaintenanceCanRevoke(ctx, s.DB, row.actor, row.owner) != row.allowed {
			t.Fatal("revocation ceiling", row)
		}
	}
}

func maintenanceIdentityFixture(t *testing.T) (*Server, identity) {
	t.Helper()
	a, actor := platformTransactionFixture(t)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/app-modules/platform-ops" {
			t.Fatal("unexpected identity fixture command")
		}
		raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Version: PlatformMaintenanceAppVersion, Installed: true, InstallationID: maintenanceTestInstallationID}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	return a, actor
}

func TestPlatformMaintenanceReinstallationAndLegacyMigrationNeverReviveAuthority(t *testing.T) {
	a, actor := maintenanceIdentityFixture(t)
	issued, e := a.Store.issuePlatformMaintenanceGrant(context.Background(), actor.ID, PlatformMaintenanceGrantInput{Commands: PlatformMaintenanceCommands(), Minutes: 60, Confirm: "GRANT NGINX MAINTENANCE"}, maintenanceTestInstallationID)
	if e != nil {
		t.Fatal(e)
	}
	out := issued.(map[string]any)
	token := out["token"].(string)
	id := out["grant_id"].(string)
	r := httptest.NewRequest("GET", "/api/platform-maintenance/plan", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, e := a.platformMaintenanceBearer(r); e != nil {
		t.Fatal(e)
	}
	// A genuine reinstall has a new native instance even at the same version.
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Version: PlatformMaintenanceAppVersion, Installed: true, InstallationID: ID()}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	if _, e := a.platformMaintenanceBearer(r); e == nil {
		t.Fatal("reinstall revived old grant")
	}
	// Recreate the old prototype schema with its exact existing rows. The real
	// migration adds an empty binding, never invents an installation authority.
	if _, e := a.Store.DB.Exec(`ALTER TABLE platform_maintenance_grants DROP COLUMN installation_id`); e != nil {
		t.Fatal(e)
	}
	var before string
	if e := a.Store.DB.QueryRow("SELECT token_hash||owner_id||commands||expires_at||revoked||created_at FROM platform_maintenance_grants WHERE token_hash=?", id).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e := a.Store.migratePlatformMaintenance(); e != nil {
		t.Fatal(e)
	}
	if e := a.Store.migratePlatformMaintenance(); e != nil {
		t.Fatal("migration not idempotent", e)
	}
	var after, binding string
	if e := a.Store.DB.QueryRow("SELECT token_hash||owner_id||commands||expires_at||revoked||created_at,installation_id FROM platform_maintenance_grants WHERE token_hash=?", id).Scan(&after, &binding); e != nil || before != after || binding != "" {
		t.Fatal("legacy grant mutated or silently rebound", e)
	}
	legacy, e := a.Store.platformMaintenanceGrant(context.Background(), id)
	if e != nil || legacy.InstallationID != "" {
		t.Fatal("legacy grant not inspectable", e)
	}
	if _, e := a.platformMaintenanceBearer(r); e == nil {
		t.Fatal("unbound prototype grant authenticated")
	}
	if _, _, _, e := a.Store.beginPlatformMaintenance(context.Background(), legacy, maintenanceTestInput(ID(), "nginx-check")); e == nil {
		t.Fatal("unbound prototype dispatched")
	}
}

func TestPlatformMaintenanceOldInstalledIdentityNeverEnablesNewCommands(t *testing.T) {
	a, _ := platformTransactionFixture(t)
	for _, row := range []struct {
		version                  string
		installed, unknown, pass bool
	}{
		{"1.2.0", true, false, false}, {"1.0", true, false, false}, {"", true, false, false},
		{"1.3", true, false, false}, {"1.3.0-compat1", true, false, false}, {"1.4.0", true, false, false},
		{PlatformMaintenanceAppVersion, false, false, false}, {PlatformMaintenanceAppVersion, true, true, false}, {PlatformMaintenanceAppVersion, true, false, true},
	} {
		a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != "GET" || r.URL.Path != "/v1/app-modules/platform-ops" {
				t.Fatal("identity check dispatched work")
			}
			raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "platform-ops", Version: row.version, Installed: row.installed, StateUnknown: row.unknown, InstallationID: maintenanceTestInstallationID}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}}
		if e := a.platformMaintenanceInstalled(context.Background()); (e == nil) != row.pass {
			t.Fatal("maintenance version gate", row, e)
		}
	}
	if SoftwareImplementationVersion("platform-ops") != PlatformMaintenanceAppVersion {
		t.Fatal("new application lacks independent implementation version")
	}
	for _, version := range []string{"1.3", "1.3.0-compat1", "1.4.0"} {
		if ValidateSoftwareUpdate("platform-ops", version) == nil {
			t.Fatal("maintenance update accepted alias", version)
		}
	}
	for _, version := range []string{"1.2.0", PlatformMaintenanceAppVersion} {
		if e := ValidateSoftwareUpdate("platform-ops", version); e != nil {
			t.Fatal("compatible exact update rejected", version, e)
		}
	}
}

func TestPlatformMaintenanceInstallQueueCannotTreatOldPackageAsNewAuthority(t *testing.T) {
	s := testStore(t)
	if _, e := s.QueueSoftwareAction("platform-ops", "install", nil, "unselected-install", "test"); e == nil {
		t.Fatal("legacy queue silently selected maintenance")
	}
	for _, version := range []string{"1.2.0", PlatformMaintenanceAppVersion} {
		job, e := s.queueSoftwareAction("platform-ops", "install", nil, version, "selected-"+version, "test")
		if e != nil {
			t.Fatal(e)
		}
		var raw string
		if e = s.DB.QueryRow("SELECT payload FROM runtime_jobs WHERE id=?", job).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		var payload struct {
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(raw), &payload) != nil || payload.Version != version {
			t.Fatal("selected signed version lost", raw)
		}
		if _, e := s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job); e != nil {
			t.Fatal(e)
		}
	}
}
