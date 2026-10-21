package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"strings"
	"testing"
)

func TestBackupJobSummaryExposesNameWithoutPayload(t *testing.T) {
	j := Job{Kind: "backup_database", Payload: `{"database":{"name":"website_db","password":"hidden-value"},"server":{"root_password":"also-hidden"}}`}
	addDatabaseJobSummary(&j)
	if j.DatabaseName != "website_db" {
		t.Fatalf("unexpected database name %q", j.DatabaseName)
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hidden-value") || strings.Contains(string(b), "also-hidden") || strings.Contains(string(b), "password") {
		t.Fatalf("private payload leaked: %s", b)
	}
}

func TestDatabaseBackupJobsOnlyExposeVerifiedArtifactSize(t *testing.T) {
	s := testStore(t)
	release := runtimecatalog.MySQL()[0]
	if err := s.RecordInstallation(release, "amd64"); err != nil {
		t.Fatal(err)
	}
	serverID, databaseID, backupID := ID(), ID(), ID()
	if _, err := s.DB.Exec(`INSERT INTO mysql_servers(id,name,release_id,port,status,created_at) VALUES(?,?,?,?,?,?)`, serverID, "mysql-test", release.ID, 13306, "running", Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO mysql_databases(id,server_id,name,username,status,created_at) VALUES(?,?,?,?,?,?)`, databaseID, serverID, "website_db", "backup_test_user", "ready", Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO mysql_backups(id,database_id,server_id,version,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?)`, backupID, databaseID, serverID, release.Version, 4096, strings.Repeat("a", 64), Now()); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(DatabaseOperation{Action: "backup_database", Database: Database{ID: databaseID, Name: "website_db"}, Backup: DatabaseBackup{ID: backupID}})
	if err != nil {
		t.Fatal(err)
	}
	successID, failedID := ID(), ID()
	for _, row := range []struct{ id, state, payload, key string }{{successID, "succeeded", string(payload), "backup-size-success"}, {failedID, "failed", "not-json", "backup-size-failed"}} {
		if _, err := s.DB.Exec(`INSERT INTO mysql_jobs(id,target_id,kind,state,payload,error,steps,idempotency_key,created_at,updated_at) VALUES(?,?,'backup_database',?,?,'','[]',?,?,?)`, row.id, serverID, row.state, row.payload, row.key, Now(), Now()); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.DatabaseBackupJobs()
	if err != nil || len(jobs) != 2 {
		t.Fatalf("jobs: %v %#v", err, jobs)
	}
	for _, job := range jobs {
		if job.ID == successID && (job.BackupBytes == nil || *job.BackupBytes != 4096 || job.DatabaseName != "website_db") {
			t.Fatalf("verified artifact missing: %#v", job)
		}
		if job.ID == failedID && job.BackupBytes != nil {
			t.Fatalf("failed job invented artifact size: %#v", job)
		}
		encoded, err := json.Marshal(job)
		if err != nil || strings.Contains(string(encoded), "not-json") {
			t.Fatalf("private job payload leaked: %v %s", err, encoded)
		}
	}
}
