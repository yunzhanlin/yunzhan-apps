package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestOverwriteBindingAndDurableDelivery(t *testing.T) {
	for _, result := range []string{"succeeded", "failed-restored", "failed-maintenance", "failed-auto-recovery"} {
		t.Run(result, func(t *testing.T) {
			s := testStore(t)
			r, _ := runtimecatalog.Find("mysql-8.4.11")
			if e := s.RecordInstallation(r, "arm64"); e != nil {
				t.Fatal(e)
			}
			server := DatabaseServer{ID: ID(), Name: "overwrite", ReleaseID: r.ID, Port: 13306, Status: "running", CreatedAt: Now()}
			if _, e := s.DB.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, server.ID, server.Name, server.ReleaseID, server.Port, server.Status, server.CreatedAt); e != nil {
				t.Fatal(e)
			}
			d := Database{ID: ID(), ServerID: server.ID, Name: "existing", Status: "ready", CreatedAt: Now(), Revision: 1}
			d.Username = "db_" + d.ID[:20]
			if _, e := s.DB.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, d.ID, d.ServerID, d.Name, d.Username, d.Status, d.CreatedAt); e != nil {
				t.Fatal(e)
			}
			request := DatabaseImport{ServerID: server.ID, Name: d.Name, Bytes: 123, TargetDatabaseID: d.ID, TargetRevision: d.Revision}
			for _, bad := range []DatabaseImport{
				{ServerID: server.ID, Name: d.Name, Bytes: 123},
				{ServerID: server.ID, Name: "other", Bytes: 123, TargetDatabaseID: d.ID, TargetRevision: 1},
				{ServerID: server.ID, Name: d.Name, Bytes: 123, TargetDatabaseID: d.ID, TargetRevision: 2},
			} {
				if _, e := s.PrepareDatabaseImport(bad, ID(), "admin"); e == nil {
					t.Fatal("target/name/revision boundary ignored")
				}
			}
			v, e := s.PrepareDatabaseImport(request, "overwrite-upload", "admin")
			if e != nil {
				t.Fatal(e)
			}
			read, e := s.DatabaseImport(v.ID)
			if e != nil || read.TargetDatabaseID != d.ID || read.TargetRevision != 1 {
				t.Fatal("binding lost", e)
			}
			same, e := s.PrepareDatabaseImport(request, "overwrite-upload", "admin")
			if e != nil || same.ID != v.ID {
				t.Fatal("prepare idempotency", e)
			}
			v.SHA256 = Hash("overwrite SQL fixture")
			v.State = "staged"
			if _, e = s.DB.Exec(`UPDATE mysql_imports SET sha256=?,state='staged' WHERE id=?`, v.SHA256, v.ID); e != nil {
				t.Fatal(e)
			}
			if _, e = s.QueueDatabase(DatabaseOperation{Action: "import_database", Server: server, Database: Database{Name: d.Name}, Import: &v}, "must-not-create", "admin"); e == nil {
				t.Fatal("overwrite upload reused for new database")
			}
			op := DatabaseOperation{Action: "overwrite_database", Server: server, Database: d, Import: &v}
			job, e := s.QueueDatabase(op, "overwrite-start", "admin")
			if e != nil {
				t.Fatal(e)
			}
			if same, e := s.QueueDatabase(op, "overwrite-start", "admin"); e != nil || same != job {
				t.Fatal("start idempotency", e)
			}
			var raw string
			s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, job).Scan(&raw)
			if e = json.Unmarshal([]byte(raw), &op); e != nil {
				t.Fatal(e)
			}
			if op.PreviousDatabase == nil || op.Database.Revision != 2 || op.Database.LastJobID != job {
				t.Fatal("original or desired revision missing")
			}
			current, _ := s.Database(d.ID)
			if current.Status != "updating" {
				t.Fatal("target not reserved")
			}
			done := DatabaseResult{State: "succeeded", DatabaseStatus: "ready"}
			if result != "succeeded" {
				done.State = "failed"
			}
			if result == "failed-maintenance" || result == "failed-auto-recovery" {
				done.DatabaseStatus = "needs_attention"
			}
			if e = s.FinishDatabase(op, done); e != nil {
				t.Fatal(e)
			}
			current, _ = s.Database(d.ID)
			if current.Status != done.DatabaseStatus {
				t.Fatal("wrong delivery state")
			}
			expectedRevision := int64(1)
			if done.State == "succeeded" {
				expectedRevision = 2
			}
			if current.Revision != expectedRevision {
				t.Fatal("wrong revision")
			}
			if result == "failed-maintenance" || result == "failed-auto-recovery" {
				if result == "failed-maintenance" {
					if e = s.RetryDatabase(job, "admin"); e != nil {
						t.Fatal(e)
					}
				}
				if e = s.FinishDatabase(op, DatabaseResult{State: "failed", DatabaseStatus: "ready"}); e != nil {
					t.Fatal(e)
				}
				current, _ = s.Database(d.ID)
				if current.Status != "ready" || current.Revision != 1 {
					t.Fatal("recovery did not restore original revision")
				}
			}
			if e = s.RetryDatabase(job, "admin"); e == nil {
				t.Fatal("delivered or restored overwrite can rerun")
			}
			if result == "failed-auto-recovery" {
				// The original revision is unchanged after rollback. The independent
				// reconciler must not use that old result to close a newer failed import.
				current, _ = s.Database(d.ID)
				second, err := s.PrepareDatabaseImport(request, "second-upload", "admin")
				if err != nil {
					t.Fatal(err)
				}
				second.SHA256 = Hash("second SQL fixture")
				second.State = "staged"
				if _, err = s.DB.Exec(`UPDATE mysql_imports SET state='staged',sha256=? WHERE id=?`, second.SHA256, second.ID); err != nil {
					t.Fatal(err)
				}
				nextJob, err := s.QueueDatabase(DatabaseOperation{Action: "overwrite_database", Server: server, Database: current, Import: &second}, "second-overwrite", "admin")
				if err != nil {
					t.Fatal(err)
				}
				var next DatabaseOperation
				if err = s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, nextJob).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal([]byte(raw), &next); err != nil {
					t.Fatal(err)
				}
				if err = s.FinishDatabase(next, DatabaseResult{State: "failed", DatabaseStatus: "needs_attention"}); err != nil {
					t.Fatal(err)
				}
				if err = s.FinishDatabase(op, DatabaseResult{State: "failed", DatabaseStatus: "ready"}); err != nil {
					t.Fatal(err)
				}
				current, _ = s.Database(d.ID)
				if current.Status != "needs_attention" {
					t.Fatal("old same-revision result closed newer maintenance")
				}
				if err = s.FinishDatabase(next, DatabaseResult{State: "failed", DatabaseStatus: "ready"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, e = s.DB.Exec(`UPDATE mysql_databases SET status='quarantined' WHERE id=?`, d.ID); e != nil {
				t.Fatal(e)
			}
			if e = s.FinishDatabase(op, DatabaseResult{State: "succeeded", DatabaseStatus: "ready"}); e != nil {
				t.Fatal(e)
			}
			current, _ = s.Database(d.ID)
			if current.Status != "quarantined" {
				t.Fatal("delayed completion overwrote later state")
			}
		})
	}
}
