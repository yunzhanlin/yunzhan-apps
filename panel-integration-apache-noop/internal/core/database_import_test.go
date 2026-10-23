package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestDatabaseImportReservationAndRecovery(t *testing.T) {
	s := testStore(t)
	release, _ := runtimecatalog.Find("mysql-8.4.11")
	if e := s.RecordInstallation(release, "arm64"); e != nil {
		t.Fatal(e)
	}
	server := DatabaseServer{ID: ID(), Name: "imports", ReleaseID: release.ID, Port: 13306, Status: "running", CreatedAt: Now()}
	if _, e := s.DB.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, server.ID, server.Name, server.ReleaseID, server.Port, server.Status, server.CreatedAt); e != nil {
		t.Fatal(e)
	}
	v, e := s.PrepareDatabaseImport(DatabaseImport{ServerID: server.ID, Name: "import_demo", Bytes: 12}, "upload-key", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.PrepareDatabaseImport(DatabaseImport{ServerID: server.ID, Name: v.Name, Bytes: 12}, "upload-key", "admin")
	if e != nil || same.ID != v.ID {
		t.Fatal("upload idempotency", e)
	}
	if _, e = s.PrepareDatabaseImport(DatabaseImport{ServerID: server.ID, Name: "other", Bytes: 12}, "upload-key", "admin"); e == nil {
		t.Fatal("reused upload identity")
	}
	op := DatabaseOperation{Action: "import_database", Server: server, Database: Database{Name: v.Name}, Import: &v}
	if _, e = s.QueueDatabase(op, "start", "admin"); e == nil {
		t.Fatal("unuploaded import accepted")
	}
	v.SHA256 = Hash("test fixture")
	v.State = "staged"
	s.DB.Exec(`UPDATE mysql_imports SET sha256=?,state='staged' WHERE id=?`, v.SHA256, v.ID)
	id, e := s.QueueDatabase(op, "start", "admin")
	if e != nil {
		t.Fatal(e)
	}
	sameID, e := s.QueueDatabase(op, "start", "admin")
	if e != nil || id != sameID {
		t.Fatal("task idempotency", e)
	}
	if _, e = s.QueueDatabase(op, "another-start", "admin"); e == nil {
		t.Fatal("same upload consumed twice")
	}
	var raw string
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw)
	var queued DatabaseOperation
	json.Unmarshal([]byte(raw), &queued)
	db, e := s.Database(queued.Database.ID)
	if e != nil || db.Status != "importing" {
		t.Fatal("unpublished target missing", e)
	}
	if _, e = s.QueueDatabase(DatabaseOperation{Action: "create_database", Server: server, Database: Database{Name: v.Name}}, "collision", "admin"); e == nil {
		t.Fatal("reserved target collision")
	}
	s.DB.Exec(`UPDATE mysql_jobs SET state='running' WHERE id=?`, id)
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishDatabase(queued, DatabaseResult{State: "failed", Error: "interrupted"}); e != nil {
		t.Fatal(e)
	}
	db, _ = s.Database(db.ID)
	if db.Status != "needs_attention" {
		t.Fatal("partial SQL published")
	}
	if e = s.RetryDatabase(id, "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishDatabase(queued, DatabaseResult{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	db, _ = s.Database(db.ID)
	v, _ = s.DatabaseImport(v.ID)
	if db.Status != "ready" || v.State != "succeeded" || v.JobID != id {
		t.Fatal("final state", db.Status, v.State)
	}
	s.DB.Exec(`UPDATE mysql_imports SET state='released' WHERE id=?`, v.ID)
	s.DB.Exec(`UPDATE mysql_databases SET status='quarantined' WHERE id=?`, db.ID)
	for _, state := range []string{"succeeded", "failed"} {
		if e = s.FinishDatabase(queued, DatabaseResult{State: state}); e != nil {
			t.Fatal(e)
		}
		db, _ = s.Database(db.ID)
		v, _ = s.DatabaseImport(v.ID)
		var jobState string
		s.DB.QueryRow(`SELECT state FROM mysql_jobs WHERE id=?`, id).Scan(&jobState)
		if db.Status != "quarantined" || v.State != "released" || jobState != "succeeded" {
			t.Fatal("delayed released import result overwrote later database state")
		}
	}
	if _, e = s.PrepareDatabaseImport(DatabaseImport{ServerID: server.ID, Name: v.Name, Bytes: 12}, "existing-db", "admin"); e == nil {
		t.Fatal("existing database allowed")
	}
	for _, value := range []DatabaseImport{{ID: ID(), ServerID: server.ID, Name: "../bad", Bytes: 1}, {ID: ID(), ServerID: server.ID, Name: "ok", Bytes: MaxSQLImport + 1}} {
		if ValidDatabaseImport(value, false) {
			t.Fatal("unsafe import accepted")
		}
	}
}
