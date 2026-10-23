package core

import (
	"encoding/json"
	"net/http"
)

type DatabaseImportRelease struct {
	Import     DatabaseImport `json:"import"`
	DatabaseID string         `json:"database_id"`
	Completed  bool           `json:"completed"`
	ReleasedAt string         `json:"released_at"`
}

func SameDatabaseImportIdentity(a, b DatabaseImport) bool {
	return a.ID == b.ID && a.ServerID == b.ServerID && a.Name == b.Name && a.Bytes == b.Bytes && a.SHA256 == b.SHA256 && a.TargetDatabaseID == b.TargetDatabaseID && a.TargetRevision == b.TargetRevision
}
func (a *Server) databaseImportReleaseRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/databases/imports/{id}/release", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		tx, e := a.Store.DB.Begin()
		if e != nil {
			fail(w, 500, "无法锁定导入记录")
			return
		}
		defer tx.Rollback()
		v, e := scanDatabaseImport(tx.QueryRow(databaseImportSelect+` WHERE i.id=?`, r.PathValue("id")))
		if e != nil {
			fail(w, 404, "导入记录不存在")
			return
		}
		if in.ConfirmName != v.Name {
			fail(w, 400, "请输入导入数据库名称确认清理")
			return
		}
		if (v.State != "succeeded" && v.State != "released") || !ValidDatabaseImport(v, true) || !ValidID(v.JobID) {
			fail(w, 409, "只可清理已经成功交付的 SQL 上传文件")
			return
		}
		var raw, state string
		if e = tx.QueryRow(`SELECT payload,state FROM mysql_jobs WHERE id=?`, v.JobID).Scan(&raw, &state); e != nil || state != "succeeded" {
			fail(w, 409, "原导入任务尚未确认成功")
			return
		}
		var op DatabaseOperation
		if json.Unmarshal([]byte(raw), &op) != nil || (op.Action != "import_database" && op.Action != "overwrite_database") || op.Import == nil || !SameDatabaseImportIdentity(*op.Import, v) || op.JobID != v.JobID {
			fail(w, 409, "导入文件与原任务不匹配")
			return
		}
		if op.Action == "overwrite_database" && (v.TargetDatabaseID != op.Database.ID || op.PreviousDatabase == nil || v.TargetRevision != op.PreviousDatabase.Revision) {
			fail(w, 409, "覆盖上传的原目标不匹配")
			return
		}
		var dbState string
		if e = tx.QueryRow(`SELECT status FROM mysql_databases WHERE id=? AND server_id=? AND name=?`, op.Database.ID, v.ServerID, v.Name).Scan(&dbState); e != nil || (dbState != "ready" && dbState != "quarantined") {
			fail(w, 409, "目标数据库正在变更或尚未交付，请先核对原任务")
			return
		}
		var out DatabaseImportRelease
		if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/imports/"+v.ID+"/release", v, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if !out.Completed || !SameDatabaseImportIdentity(out.Import, v) || out.Import.JobID != v.JobID || out.DatabaseID != op.Database.ID {
			fail(w, 502, "无法核对清理结果")
			return
		}
		if _, e = tx.Exec(`UPDATE mysql_imports SET state='released' WHERE id=? AND job_id=?`, v.ID, v.JobID); e != nil {
			fail(w, 500, "无法保存清理状态，可重复核对同一记录")
			return
		}
		if v.State != "released" {
			if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'mysql.import.release',?,'success',?)`, u.Username, v.ID, Now()); e != nil {
				fail(w, 500, "无法保存清理审计")
				return
			}
		}
		if e = tx.Commit(); e != nil {
			fail(w, 500, "清理状态未提交，可重复核对")
			return
		}
		send(w, 200, out)
	}))
}
