//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func releaseFixture(t *testing.T) (string, core.DatabaseImport, mysqlJob) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires private root-owned files in Linux VM")
	}
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	body := "CREATE TABLE notes(id INT);\n"
	server := core.DatabaseServer{ID: core.ID(), Name: "release", ReleaseID: "mysql-8.4.11", Port: 13306, Status: "running", CreatedAt: core.Now()}
	v, e := stageSQLImport(context.Background(), base, core.DatabaseImport{ID: core.ID(), ServerID: server.ID, Name: "notes", Bytes: int64(len(body))}, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	v.JobID = core.ID()
	v.State = "succeeded"
	d := core.Database{ID: core.ID(), ServerID: server.ID, Name: v.Name, Status: "importing"}
	d.Username = "db_" + d.ID[:20]
	j := mysqlJob{Operation: core.DatabaseOperation{JobID: v.JobID, Action: "import_database", Server: server, Database: d, Import: &v}, Result: core.DatabaseResult{State: "succeeded"}}
	if e = writeJSON(filepath.Join(base, v.ID+".claim.json"), map[string]string{"JobID": v.JobID, "DatabaseID": d.ID}); e != nil {
		t.Fatal(e)
	}
	return base, v, j
}
func TestSQLImportReleaseOwnershipAndRecovery(t *testing.T) {
	for _, name := range []string{"success", "failed-journal", "wrong-claim", "wrong-job", "wrong-server", "missing-source", "tampered-source", "public-source", "hardlink", "symlink", "locked", "pending-before-unlink", "pending-after-unlink", "completed-source-reappeared"} {
		t.Run(name, func(t *testing.T) {
			base, v, j := releaseFixture(t)
			sql := filepath.Join(base, v.ID+".sql")
			switch name {
			case "failed-journal":
				j.Result.State = "failed"
			case "wrong-claim":
				writeJSON(filepath.Join(base, v.ID+".claim.json"), map[string]string{"JobID": core.ID(), "DatabaseID": j.Operation.Database.ID})
			case "wrong-job":
				j.Operation.JobID = core.ID()
			case "wrong-server":
				j.Operation.Server.ID = "../outside"
			case "missing-source":
				os.Remove(sql)
			case "tampered-source":
				os.WriteFile(sql, []byte("changed SQL"), 0600)
			case "public-source":
				os.Chmod(sql, 0644)
			case "hardlink":
				os.Link(sql, sql+".link")
			case "symlink":
				os.Rename(sql, sql+".original")
				os.Symlink(sql+".original", sql)
			case "locked":
				f, e := os.OpenFile(filepath.Join(base, "upload.lock"), os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
					t.Fatal(e)
				}
			case "pending-before-unlink", "pending-after-unlink", "completed-source-reappeared":
				marker := core.DatabaseImportRelease{Import: v, DatabaseID: j.Operation.Database.ID}
				if name == "pending-after-unlink" {
					os.Remove(sql)
				}
				if name == "completed-source-reappeared" {
					marker.Completed = true
					marker.ReleasedAt = core.Now()
				}
				if e := writeJSON(filepath.Join(base, v.ID+".release.json"), marker); e != nil {
					t.Fatal(e)
				}
			}
			out, e := releaseSQLImport(context.Background(), base, v, j)
			success := name == "success" || name == "pending-before-unlink" || name == "pending-after-unlink"
			if !success {
				if e == nil {
					t.Fatal("unsafe cleanup accepted")
				}
				if name != "missing-source" {
					if _, e = os.Lstat(sql); e != nil {
						t.Fatal("failed cleanup removed source", e)
					}
				}
				return
			}
			if e != nil || !out.Completed || out.ReleasedAt == "" {
				t.Fatal("cleanup failed", e)
			}
			if _, e = os.Lstat(sql); !os.IsNotExist(e) {
				t.Fatal("SQL not removed")
			}
			again, e := releaseSQLImport(context.Background(), base, v, j)
			if e != nil || again.ReleasedAt != out.ReleasedAt {
				t.Fatal("repeat cleanup changed result", e)
			}
			for _, suffix := range []string{".json", ".claim.json", ".release.json"} {
				if _, e = os.Stat(filepath.Join(base, v.ID+suffix)); e != nil {
					t.Fatal("metadata lost", e)
				}
			}
			if _, e = stageSQLImport(context.Background(), base, v, strings.NewReader("CREATE TABLE notes(id INT);\n")); e == nil {
				t.Fatal("released upload ID reused")
			}
			if _, e = os.Lstat(sql); !os.IsNotExist(e) {
				t.Fatal("released source resurrected")
			}
		})
	}
}

// The optional real fixture exercises the actual original operation after release.
// It must be a journal created by the local acceptance script, never a forged SQL task.
func TestReleasedImportActualReplay(t *testing.T) {
	id := os.Getenv("PANEL_RELEASED_IMPORT_JOB")
	if id == "" {
		t.Skip("explicit completed fixture required")
	}
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("invalid fixture")
	}
	raw, e := os.ReadFile(filepath.Join(mysqlJobs, id+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var j mysqlJob
	if e = json.Unmarshal(raw, &j); e != nil {
		t.Fatal(e)
	}
	if j.Operation.Import == nil || j.Result.State != "succeeded" {
		t.Fatal("requires succeeded import journal")
	}
	root, e := importRoot(mysqlImports)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	marker, e := readImportRelease(root, j.Operation.Import.ID)
	if e != nil || !marker.Completed {
		t.Fatal("requires completed cleanup", e)
	}
	logged := false
	if e = importMySQL(context.Background(), j.Operation, func(message string) { logged = strings.Contains(message, "保留数据库当前内容") }); e != nil {
		t.Fatal(e)
	}
	if !logged {
		t.Fatal("original SQL was not bypassed")
	}
	if _, e = stageSQLImport(context.Background(), mysqlImports, *j.Operation.Import, strings.NewReader("")); e == nil {
		t.Fatal("real released upload reopened")
	}
}
