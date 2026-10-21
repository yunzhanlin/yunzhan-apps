package core

import (
	"database/sql"
	"errors"
)

func (s *Store) migrateDatabaseOverwrite() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mysql_import_targets(import_id TEXT PRIMARY KEY REFERENCES mysql_imports(id),database_id TEXT NOT NULL REFERENCES mysql_databases(id),revision INTEGER NOT NULL CHECK(revision>0));
 INSERT OR IGNORE INTO schema_migrations VALUES(13,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

const databaseImportSelect = `SELECT i.id,i.server_id,i.name,i.bytes,i.sha256,i.state,i.job_id,i.created_at,COALESCE(t.database_id,''),COALESCE(t.revision,0) FROM mysql_imports i LEFT JOIN mysql_import_targets t ON t.import_id=i.id`

func scanDatabaseImport(row interface{ Scan(...any) error }) (DatabaseImport, error) {
	var v DatabaseImport
	e := row.Scan(&v.ID, &v.ServerID, &v.Name, &v.Bytes, &v.SHA256, &v.State, &v.JobID, &v.CreatedAt, &v.TargetDatabaseID, &v.TargetRevision)
	return v, e
}
func queueDatabaseOverwrite(tx *sql.Tx, op *DatabaseOperation) error {
	if op.Import == nil || !ValidDatabaseImport(*op.Import, true) || op.Import.TargetDatabaseID != op.Database.ID || op.Import.ServerID != op.Server.ID || op.Import.Name != op.Database.Name || op.Import.TargetRevision != op.Database.Revision {
		return errors.New("覆盖上传与目标数据库或修订不匹配")
	}
	v, e := scanDatabaseImport(tx.QueryRow(databaseImportSelect+` WHERE i.id=?`, op.Import.ID))
	if e != nil {
		return e
	}
	if v.State != "staged" || !SameDatabaseImportIdentity(v, *op.Import) || v.JobID != "" {
		return errors.New("覆盖上传尚未就绪或已被任务认领")
	}
	d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, op.Database.ID))
	if e != nil {
		return e
	}
	if d.Status != "ready" || d.ServerID != op.Server.ID || d.Name != v.Name || d.Revision != v.TargetRevision {
		return errors.New("目标数据库已变化，请重新选择并上传")
	}
	refs, e := databaseAccountReferences(tx, d.ID)
	if e != nil {
		return e
	}
	for _, ref := range refs {
		if ref.Status != "quarantined" {
			return errors.New("请先回收引用此库的独立账号或解除其授权")
		}
	}
	op.PreviousDatabase = &d
	op.Database = d
	op.Database.Revision++
	op.Database.Status = "ready"
	_, e = tx.Exec(`UPDATE mysql_databases SET status='updating' WHERE id=?`, d.ID)
	return e
}
func finishDatabaseOverwrite(tx *sql.Tx, op DatabaseOperation, result DatabaseResult) error {
	if op.PreviousDatabase == nil || op.Import == nil {
		return errors.New("覆盖任务缺少原始身份")
	}
	d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, op.Database.ID))
	if e != nil {
		return e
	}
	if d.Revision != op.PreviousDatabase.Revision || (d.Status != "updating" && d.Status != "needs_attention") {
		return errors.New("覆盖任务原修订已变化，拒绝修改数据库状态")
	}
	status := "needs_attention"
	if result.DatabaseStatus == "ready" {
		status = "ready"
	}
	if result.State == "succeeded" && status != "ready" {
		return errors.New("覆盖任务尚未证明数据库和原凭据可用")
	}
	if _, e = tx.Exec(`UPDATE mysql_databases SET status=? WHERE id=?`, status, d.ID); e != nil {
		return e
	}
	if result.State == "succeeded" {
		_, e = tx.Exec(`INSERT INTO mysql_database_lifecycle(database_id,revision,last_job_id) VALUES(?,?,?) ON CONFLICT(database_id) DO UPDATE SET revision=excluded.revision,last_job_id=excluded.last_job_id`, d.ID, op.Database.Revision, op.JobID)
	}
	return e
}
