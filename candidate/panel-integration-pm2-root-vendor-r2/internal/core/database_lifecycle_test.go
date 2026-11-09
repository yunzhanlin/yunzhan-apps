package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestDatabaseLifecycleReferencesRevisionAndRetry(t *testing.T) {
	s := testStore(t)
	r, _ := runtimecatalog.Find("mysql-8.4.11")
	if e := s.RecordInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	server := DatabaseServer{ID: ID(), Name: "lifecycle", ReleaseID: r.ID, Port: 13306, Status: "running", CreatedAt: Now()}
	if _, e := s.DB.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, server.ID, server.Name, server.ReleaseID, server.Port, server.Status, server.CreatedAt); e != nil {
		t.Fatal(e)
	}
	d := Database{ID: ID(), ServerID: server.ID, Name: "lifecycle", Status: "ready", CreatedAt: Now()}
	d.Username = "db_" + d.ID[:20]
	if _, e := s.DB.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, d.ID, d.ServerID, d.Name, d.Username, d.Status, d.CreatedAt); e != nil {
		t.Fatal(e)
	}
	d, e := s.Database(d.ID)
	if e != nil || d.Revision != 1 {
		t.Fatal("legacy database revision", e)
	}
	a := DatabaseAccount{ID: ID(), ServerID: server.ID, Name: "scope", Role: "readonly", DatabaseIDs: []string{d.ID}, Enabled: true, Status: "ready", Revision: 1, CreatedAt: Now(), UpdatedAt: Now()}
	a.Username = "app_" + a.ID[:20]
	ids, _ := json.Marshal(a.DatabaseIDs)
	if _, e = s.DB.Exec(`INSERT INTO mysql_accounts VALUES(?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.ServerID, a.Name, a.Username, a.Role, string(ids), a.Enabled, a.Status, a.Revision, a.CreatedAt, a.UpdatedAt); e != nil {
		t.Fatal(e)
	}
	request := DatabaseOperation{Action: "quarantine_database", Server: server, Database: d}
	if _, e = s.QueueDatabase(request, "blocked-reference", "admin"); e == nil {
		t.Fatal("live account reference ignored")
	}
	if _, e = s.DB.Exec(`UPDATE mysql_accounts SET status='quarantined' WHERE id=?`, a.ID); e != nil {
		t.Fatal(e)
	}
	job, e := s.QueueDatabase(request, "recycle", "admin")
	if e != nil {
		t.Fatal(e)
	}
	load := func(id string) DatabaseOperation {
		t.Helper()
		var raw string
		if e := s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		var op DatabaseOperation
		if e := json.Unmarshal([]byte(raw), &op); e != nil {
			t.Fatal(e)
		}
		return op
	}
	op := load(job)
	if op.PreviousDatabase == nil || op.Database.Revision != 2 || op.Database.LastJobID != job || op.Database.Status != "quarantined" {
		t.Fatal("missing durable lifecycle intent")
	}
	if e = s.FinishDatabase(op, DatabaseResult{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	archived, _ := s.Database(d.ID)
	if archived.Status != "quarantined" || archived.Revision != 2 {
		t.Fatal("recycle not committed")
	}
	// A retained account dependency may not be reactivated before its database.
	account, _ := s.DatabaseAccount(a.ID)
	if _, e = s.QueueDatabase(DatabaseOperation{Action: "restore_account", Server: server, Account: &account}, "restore-too-early", "admin"); e == nil {
		t.Fatal("account restored before database")
	}
	stale := archived
	stale.Revision = 1
	if _, e = s.QueueDatabase(DatabaseOperation{Action: "recover_database", Server: server, Database: stale}, "stale", "admin"); e == nil {
		t.Fatal("stale database restore")
	}
	job, e = s.QueueDatabase(DatabaseOperation{Action: "recover_database", Server: server, Database: archived}, "recover", "admin")
	if e != nil {
		t.Fatal(e)
	}
	op = load(job)
	if e = s.FinishDatabase(op, DatabaseResult{State: "failed"}); e != nil {
		t.Fatal(e)
	}
	failed, _ := s.Database(d.ID)
	if failed.Status != "needs_attention" || failed.Revision != 2 {
		t.Fatal("failed recovery published revision")
	}
	if e = s.RetryDatabase(job, "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishDatabase(op, DatabaseResult{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	ready, _ := s.Database(d.ID)
	if ready.Status != "ready" || ready.Revision != 3 {
		t.Fatal("recovery not committed")
	}
	if replay, e := s.QueueDatabase(request, "recycle", "admin"); e != nil || replay == job {
		t.Fatal("original idempotent result unavailable", e)
	}
	request.Database.Revision = 2
	if _, e = s.QueueDatabase(request, "recycle", "admin"); e == nil {
		t.Fatal("changed revision reused idempotency key")
	}
}
