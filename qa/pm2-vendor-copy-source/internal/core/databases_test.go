package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestDatabaseInstanceIsolationAndRecovery(t *testing.T) {
	s := testStore(t)
	releases := runtimecatalog.MySQL()
	if len(releases) != 2 {
		t.Fatal("expected two MySQL releases")
	}
	for _, r := range releases {
		if e := s.RecordInstallation(r, "arm64"); e != nil {
			t.Fatal(e)
		}
	}
	op := DatabaseOperation{Action: "create_instance", Server: DatabaseServer{Name: "mysql-main", ReleaseID: "mysql-8.4.11", Port: 13306}}
	id, e := s.QueueDatabase(op, "create-main", "admin")
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.QueueDatabase(op, "create-main", "admin")
	if e != nil || again != id {
		t.Fatal("idempotency", e)
	}
	changed := op
	changed.Server.Port = 13307
	if _, e = s.QueueDatabase(changed, "create-main", "admin"); e == nil {
		t.Fatal("key reused across changed request")
	}
	var raw string
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw)
	var actual DatabaseOperation
	json.Unmarshal([]byte(raw), &actual)
	if !ValidID(actual.Server.ID) {
		t.Fatal("missing immutable instance ID")
	}
	if _, e = s.QueueDatabase(DatabaseOperation{Action: "stop_instance", Server: actual.Server}, "stop-busy", "admin"); e == nil {
		t.Fatal("concurrent instance operation accepted")
	}
	s.DB.Exec(`UPDATE mysql_jobs SET state='running' WHERE id=?`, id)
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	var state string
	s.DB.QueryRow(`SELECT state FROM mysql_jobs WHERE id=?`, id).Scan(&state)
	if state != "queued" {
		t.Fatal("interrupted operation not recoverable")
	}
	if e = s.FinishDatabase(actual, DatabaseResult{State: "succeeded", ServerStatus: "running"}); e != nil {
		t.Fatal(e)
	}
	var dir, socket, version string
	e = s.DB.QueryRow(`SELECT data_dir,socket_path,installation_id FROM runtime_instances WHERE id=?`, actual.Server.ID).Scan(&dir, &socket, &version)
	if e != nil || version != actual.Server.ReleaseID || dir != "/srv/panel/mysql/"+actual.Server.ID+"/data" || socket != "/run/panel-mysql-"+actual.Server.ID+"/mysql.sock" {
		t.Fatal("instance binding", e)
	}
	duplicate := op
	duplicate.Server.Name = "other"
	if _, e = s.QueueDatabase(duplicate, "port-conflict", "admin"); e == nil {
		t.Fatal("duplicate port allowed")
	}
	for _, name := range []string{"../mysql", "db; DROP TABLE users", "UPPER", ""} {
		if _, e = s.QueueDatabase(DatabaseOperation{Action: "create_database", Server: actual.Server, Database: Database{Name: name}}, "invalid-"+name, "admin"); e == nil {
			t.Fatal("unsafe database name accepted")
		}
	}
	dbjob, e := s.QueueDatabase(DatabaseOperation{Action: "create_database", Server: actual.Server, Database: Database{Name: "app_data"}}, "app-db", "admin")
	if e != nil {
		t.Fatal(e)
	}
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, dbjob).Scan(&raw)
	if len(raw) == 0 {
		t.Fatal("missing operation")
	}
	var dbop DatabaseOperation
	json.Unmarshal([]byte(raw), &dbop)
	if e = s.FinishDatabase(dbop, DatabaseResult{State: "failed", Error: "simulated failure"}); e != nil {
		t.Fatal(e)
	}
	db, e := s.Database(dbop.Database.ID)
	if e != nil || db.Status != "needs_attention" {
		t.Fatal("failed database reported ready")
	}
	if e = s.RetryDatabase(dbjob, "admin"); e != nil {
		t.Fatal(e)
	}
	xs, e := s.Jobs()
	if e != nil || len(xs) != 2 {
		t.Fatal("database jobs absent from combined list", len(xs), e)
	}
}
func TestMigrationReservesBothInstances(t *testing.T) {
	s := testStore(t)
	for _, r := range runtimecatalog.MySQL() {
		if e := s.RecordInstallation(r, "arm64"); e != nil {
			t.Fatal(e)
		}
	}
	servers := []DatabaseServer{}
	for i, release := range []string{"mysql-8.0.46", "mysql-8.4.11"} {
		id, e := s.QueueDatabase(DatabaseOperation{Action: "create_instance", Server: DatabaseServer{Name: release, ReleaseID: release, Port: 13306 + i}}, release, "admin")
		if e != nil {
			t.Fatal(e)
		}
		var raw string
		s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw)
		var op DatabaseOperation
		json.Unmarshal([]byte(raw), &op)
		if e = s.FinishDatabase(op, DatabaseResult{State: "succeeded", ServerStatus: "running"}); e != nil {
			t.Fatal(e)
		}
		servers = append(servers, op.Server)
	}
	id, e := s.QueueDatabase(DatabaseOperation{Action: "create_database", Server: servers[0], Database: Database{Name: "migration_probe"}}, "db", "admin")
	if e != nil {
		t.Fatal(e)
	}
	var raw string
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw)
	var created DatabaseOperation
	json.Unmarshal([]byte(raw), &created)
	if e = s.FinishDatabase(created, DatabaseResult{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	op := DatabaseOperation{Action: "migrate_database", Server: servers[0], Database: created.Database, TargetServer: servers[1]}
	id, e = s.QueueDatabase(op, "migrate", "admin")
	if e != nil {
		t.Fatal(e)
	}
	for _, server := range servers {
		if _, e = s.QueueDatabase(DatabaseOperation{Action: "stop_instance", Server: server}, "stop-"+server.ID, "admin"); e == nil {
			t.Fatal("migration did not reserve both instances")
		}
	}
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, id).Scan(&raw)
	json.Unmarshal([]byte(raw), &op)
	backup := DatabaseBackup{ID: ID(), DatabaseID: op.Database.ID, ServerID: op.Server.ID, Version: "8.0.46", Bytes: 123, SHA256: Hash("backup"), CreatedAt: Now()}
	if e = s.FinishDatabase(op, DatabaseResult{State: "failed", Error: "interrupted", Backup: backup}); e != nil {
		t.Fatal(e)
	}
	dest, e := s.Database(op.TargetDatabase.ID)
	if e != nil || dest.Status != "needs_attention" {
		t.Fatal("target incorrectly ready")
	}
	backups, e := s.DatabaseBackups()
	if e != nil || len(backups) != 1 {
		t.Fatal("failure lost recovery backup")
	}
	busyID, e := s.QueueDatabase(DatabaseOperation{Action: "stop_instance", Server: servers[1]}, "target-busy", "admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RetryDatabase(id, "admin"); e == nil {
		t.Fatal("retry ignored busy migration target")
	}
	var busyRaw string
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, busyID).Scan(&busyRaw)
	var busyOp DatabaseOperation
	json.Unmarshal([]byte(busyRaw), &busyOp)
	if e = s.FinishDatabase(busyOp, DatabaseResult{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	if e = s.RetryDatabase(id, "admin"); e != nil {
		t.Fatal(e)
	}
}
