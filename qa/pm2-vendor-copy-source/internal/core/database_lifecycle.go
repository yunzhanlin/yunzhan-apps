package core

import (
	"database/sql"
	"errors"
	"net/http"
)

func (s *Store) migrateDatabaseLifecycle() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mysql_database_lifecycle(database_id TEXT PRIMARY KEY REFERENCES mysql_databases(id),revision INTEGER NOT NULL,last_job_id TEXT NOT NULL);
 INSERT OR IGNORE INTO schema_migrations VALUES(12,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

const databaseLifecycleSelect = `SELECT d.id,d.server_id,d.name,d.username,d.status,d.created_at,COALESCE(l.revision,1),COALESCE(l.last_job_id,'') FROM mysql_databases d LEFT JOIN mysql_database_lifecycle l ON l.database_id=d.id`

func scanLifecycleDatabase(row interface{ Scan(...any) error }) (Database, error) {
	var d Database
	e := row.Scan(&d.ID, &d.ServerID, &d.Name, &d.Username, &d.Status, &d.CreatedAt, &d.Revision, &d.LastJobID)
	return d, e
}
func databaseLifecycleAction(action string) bool {
	return action == "quarantine_database" || action == "recover_database"
}

type DatabaseRemovalPlan struct {
	DatabaseID     string                     `json:"database_id"`
	Revision       int64                      `json:"revision"`
	Status         string                     `json:"status"`
	Connections    int                        `json:"connections"`
	References     []DatabaseAccountReference `json:"references"`
	Accounts       []DatabaseAccount          `json:"accounts"`
	BackupCount    int                        `json:"backup_count"`
	BlockedReasons []string                   `json:"blocked_reasons"`
}

func databaseAccountReferences(tx interface {
	Query(string, ...any) (*sql.Rows, error)
}, id string) ([]DatabaseAccount, error) {
	rows, e := tx.Query(`SELECT `+accountColumns+` FROM mysql_accounts WHERE EXISTS(SELECT 1 FROM json_each(mysql_accounts.database_ids) WHERE value=?) ORDER BY name,id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DatabaseAccount{}
	for rows.Next() {
		a, e := scanDatabaseAccount(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func queueDatabaseLifecycle(tx *sql.Tx, op *DatabaseOperation) error {
	d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, op.Database.ID))
	if e != nil {
		return errors.New("数据库不存在")
	}
	expected := "ready"
	desired := "quarantined"
	if op.Action == "recover_database" {
		expected = "quarantined"
		desired = "ready"
	}
	if d.ServerID != op.Server.ID || d.Status != expected || d.Revision != op.Database.Revision {
		return errors.New("数据库版本或状态变化，请刷新后重试")
	}
	refs, e := databaseAccountReferences(tx, d.ID)
	if e != nil {
		return e
	}
	for _, a := range refs {
		if a.Status != "quarantined" {
			return errors.New("数据库仍有使用中的账号绑定，请先回收账号或调整授权范围")
		}
	}
	op.PreviousDatabase = &d
	op.Database = d
	op.Database.Revision++
	op.Database.Status = desired
	_, e = tx.Exec(`UPDATE mysql_databases SET status='updating' WHERE id=?`, d.ID)
	return e
}
func finishDatabaseLifecycle(tx *sql.Tx, op DatabaseOperation, result DatabaseResult) error {
	if result.State != "succeeded" {
		_, e := tx.Exec(`UPDATE mysql_databases SET status='needs_attention' WHERE id=?`, op.Database.ID)
		return e
	}
	if _, e := tx.Exec(`UPDATE mysql_databases SET status=? WHERE id=? AND server_id=?`, op.Database.Status, op.Database.ID, op.Server.ID); e != nil {
		return e
	}
	_, e := tx.Exec(`INSERT INTO mysql_database_lifecycle VALUES(?,?,?) ON CONFLICT(database_id) DO UPDATE SET revision=excluded.revision,last_job_id=excluded.last_job_id`, op.Database.ID, op.Database.Revision, op.JobID)
	return e
}
func (a *Server) databaseRemovalPlan(r *http.Request, d Database) (DatabaseRemovalPlan, error) {
	var plan DatabaseRemovalPlan
	if e := a.Executor.Call(r.Context(), "POST", "/v1/databases/removal-plan", map[string]any{"server_id": d.ServerID, "database_id": d.ID, "revision": d.Revision}, &plan); e != nil {
		return plan, e
	}
	refs, e := databaseAccountReferences(a.Store.DB, d.ID)
	if e != nil {
		return plan, e
	}
	plan.Accounts = refs
	for _, a := range refs {
		if a.Status != "quarantined" {
			plan.BlockedReasons = append(plan.BlockedReasons, "仍有使用中的账号绑定，请先回收账号或调整授权范围")
			break
		}
	}
	e = a.Store.DB.QueryRow(`SELECT count(*) FROM mysql_backups WHERE database_id=?`, d.ID).Scan(&plan.BackupCount)
	return plan, e
}
func (a *Server) databaseLifecycleRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/items/{id}/latest-job", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Database(r.PathValue("id")); e != nil {
			fail(w, 404, "数据库不存在")
			return
		}
		var id string
		if e := a.Store.DB.QueryRow(`SELECT id FROM mysql_jobs WHERE json_extract(payload,'$.database.id')=? OR json_extract(payload,'$.target_database.id')=? ORDER BY created_at DESC,rowid DESC LIMIT 1`, r.PathValue("id"), r.PathValue("id")).Scan(&id); e != nil {
			fail(w, 404, "数据库任务不存在")
			return
		}
		send(w, 200, map[string]string{"job_id": id})
	}))
	m.HandleFunc("GET /api/databases/items/{id}/removal-plan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		d, e := a.Store.Database(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库不存在")
			return
		}
		if d.Status != "ready" && d.Status != "quarantined" {
			fail(w, 409, "请先核对数据库的原任务")
			return
		}
		plan, e := a.databaseRemovalPlan(r, d)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, plan)
	}))
	for _, action := range []string{"quarantine", "recover"} {
		m.HandleFunc("POST /api/databases/items/{id}/"+action, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			d, e := a.Store.Database(r.PathValue("id"))
			if e != nil {
				fail(w, 404, "数据库不存在")
				return
			}
			s, e := a.Store.DatabaseServer(d.ServerID)
			if e != nil || s.Status != "running" {
				fail(w, 409, "请选择运行中的实例")
				return
			}
			var in struct {
				Revision    int64  `json:"revision"`
				ConfirmName string `json:"confirm_name"`
			}
			if !decode(w, r, &in) {
				return
			}
			if in.ConfirmName != d.Name {
				fail(w, 400, "请输入数据库名称确认")
				return
			}
			if d.Status == "ready" || d.Status == "quarantined" {
				plan, e := a.databaseRemovalPlan(r, d)
				if e != nil {
					fail(w, 409, e.Error())
					return
				}
				if len(plan.BlockedReasons) > 0 {
					fail(w, 409, plan.BlockedReasons[0])
					return
				}
			}
			d.Revision = in.Revision
			kind := "quarantine_database"
			if action == "recover" {
				kind = "recover_database"
			}
			a.queueDatabase(w, r, u, DatabaseOperation{Action: kind, Server: s, Database: d})
		}))
	}
}
