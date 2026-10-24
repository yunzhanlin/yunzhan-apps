package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const MaxSQLImport int64 = 512 * 1024 * 1024

type DatabaseImport struct {
	TargetDatabaseID string `json:"target_database_id,omitempty"`
	TargetRevision   int64  `json:"target_revision,omitempty"`
	ID               string `json:"id"`
	ServerID         string `json:"server_id"`
	Name             string `json:"name"`
	Bytes            int64  `json:"bytes"`
	SHA256           string `json:"sha256"`
	State            string `json:"state"`
	JobID            string `json:"job_id"`
	CreatedAt        string `json:"created_at"`
}

func ValidDatabaseImport(v DatabaseImport, staged bool) bool {
	targetOK := (v.TargetDatabaseID == "" && v.TargetRevision == 0) || (ValidID(v.TargetDatabaseID) && v.TargetRevision > 0)
	return targetOK && ValidID(v.ID) && ValidID(v.ServerID) && ValidDatabaseName(v.Name) && v.Bytes > 0 && v.Bytes <= MaxSQLImport && (!staged || (len(v.SHA256) == 64 && ValidID(v.SHA256[:32]) && ValidID(v.SHA256[32:])))
}
func (s *Store) migrateDatabaseImports() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mysql_imports(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES mysql_servers(id),name TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL DEFAULT '',state TEXT NOT NULL,job_id TEXT NOT NULL DEFAULT '',idempotency_key TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL);
 INSERT OR IGNORE INTO schema_migrations VALUES(10,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func (s *Store) DatabaseImport(id string) (DatabaseImport, error) {
	return scanDatabaseImport(s.DB.QueryRow(databaseImportSelect+` WHERE i.id=?`, id))
}
func (s *Store) PrepareDatabaseImport(v DatabaseImport, key, actor string) (DatabaseImport, error) {
	if key == "" || len(key) > 128 {
		return v, errors.New("请提供有效幂等键")
	}
	v.ID = ID()
	v.State = "awaiting_upload"
	v.CreatedAt = Now()
	if !ValidDatabaseImport(v, false) {
		return v, errors.New("请选择实例、新数据库名与 1 字节至 512 MiB 的普通 SQL 文件")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	old, e := scanDatabaseImport(tx.QueryRow(databaseImportSelect+` WHERE i.idempotency_key=?`, key))
	if e == nil {
		if old.ServerID != v.ServerID || old.Name != v.Name || old.Bytes != v.Bytes || old.TargetDatabaseID != v.TargetDatabaseID || old.TargetRevision != v.TargetRevision {
			return v, errors.New("幂等键已用于其他上传")
		}
		return old, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return v, e
	}
	var n int
	if e = tx.QueryRow(`SELECT count(*) FROM mysql_databases WHERE server_id=? AND name=?`, v.ServerID, v.Name).Scan(&n); e != nil {
		return v, e
	}
	if v.TargetDatabaseID != "" {
		d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, v.TargetDatabaseID))
		if e != nil || d.ServerID != v.ServerID || d.Name != v.Name || d.Revision != v.TargetRevision || d.Status != "ready" {
			return v, errors.New("覆盖目标、实例或修订已变化，请重新选择")
		}
	} else if n > 0 {
		return v, errors.New("目标实例已有同名数据库；导入只创建新库")
	}
	if e = tx.QueryRow(`SELECT count(*) FROM mysql_imports WHERE state='awaiting_upload'`).Scan(&n); e != nil {
		return v, e
	}
	if n >= 100 {
		return v, errors.New("待上传记录已达上限，请先完成已有上传")
	}
	_, e = tx.Exec(`INSERT INTO mysql_imports(id,server_id,name,bytes,state,idempotency_key,created_at) VALUES(?,?,?,?,?,?,?)`, v.ID, v.ServerID, v.Name, v.Bytes, v.State, key, v.CreatedAt)
	if e != nil {
		return v, e
	}
	if v.TargetDatabaseID != "" {
		if _, e = tx.Exec(`INSERT INTO mysql_import_targets VALUES(?,?,?)`, v.ID, v.TargetDatabaseID, v.TargetRevision); e != nil {
			return v, e
		}
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'mysql.import.prepare',?,'success',?)`, actor, v.ID, Now())
	if e != nil {
		return v, e
	}
	return v, tx.Commit()
}
func (a *Server) databaseImportRoutes(m *http.ServeMux) {
	a.databaseOverwriteRoutes(m)
	a.databaseImportReleaseRoutes(m)
	m.HandleFunc("GET /api/databases/imports", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		rows, e := a.Store.DB.Query(databaseImportSelect + ` WHERE i.state!='canceled' ORDER BY i.created_at DESC,i.rowid DESC LIMIT 100`)
		if e != nil {
			fail(w, 500, "读取导入记录失败")
			return
		}
		defer rows.Close()
		out := []DatabaseImport{}
		for rows.Next() {
			v, e := scanDatabaseImport(rows)
			if e != nil {
				fail(w, 500, "读取导入记录失败")
				return
			}
			out = append(out, v)
		}
		if rows.Err() != nil {
			fail(w, 500, "读取导入记录失败")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/databases/imports/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.DatabaseImport(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "导入记录不存在")
			return
		}
		if v.State != "awaiting_upload" && v.State != "staged" {
			fail(w, 409, "只有尚未创建任务的上传可以移除")
			return
		}
		// Hold the same database transaction used by QueueDatabase while removing the
		// spool, so a simultaneous start cannot consume a deleted import.
		tx, e := a.Store.DB.Begin()
		if e != nil {
			fail(w, 500, "无法锁定导入记录")
			return
		}
		defer tx.Rollback()
		var state string
		if e = tx.QueryRow(`SELECT state FROM mysql_imports WHERE id=?`, v.ID).Scan(&state); e != nil || (state != "awaiting_upload" && state != "staged") {
			fail(w, 409, "导入记录已变化")
			return
		}
		var out any
		if e = a.Executor.Call(r.Context(), "DELETE", "/v1/databases/imports/"+v.ID, nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if _, e = tx.Exec(`UPDATE mysql_imports SET state='canceled' WHERE id=?`, v.ID); e != nil {
			fail(w, 500, "保存移除状态失败")
			return
		}
		if e = tx.Commit(); e != nil {
			fail(w, 500, "保存移除状态失败")
			return
		}
		_ = a.Store.Audit(u.Username, "mysql.import.cancel", v.ID, "success")
		send(w, 200, map[string]bool{"removed": true})
	}))

	m.HandleFunc("POST /api/databases/imports", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ServerID string `json:"server_id"`
			Name     string `json:"name"`
			Bytes    int64  `json:"bytes"`
		}
		if !decode(w, r, &in) {
			return
		}
		server, e := a.Store.DatabaseServer(in.ServerID)
		if e != nil || server.Status != "running" {
			fail(w, 409, "请选择运行中的 MySQL 实例")
			return
		}
		v, e := a.Store.PrepareDatabaseImport(DatabaseImport{ServerID: in.ServerID, Name: in.Name, Bytes: in.Bytes}, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, v)
	}))
	m.HandleFunc("GET /api/databases/imports/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.DatabaseImport(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "导入记录不存在")
			return
		}
		send(w, 200, v)
	}))
	m.HandleFunc("POST /api/databases/imports/{id}/upload", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.DatabaseImport(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "导入记录不存在")
			return
		}
		if v.State != "awaiting_upload" || r.ContentLength != v.Bytes {
			fail(w, 409, "上传状态或文件长度不符，请读取导入记录确认结果")
			return
		}
		deadline := time.Now().Add(30 * time.Minute)
		ctrl := http.NewResponseController(w)
		_ = ctrl.SetReadDeadline(deadline)
		_ = ctrl.SetWriteDeadline(deadline)
		q := url.Values{"server_id": {v.ServerID}, "name": {v.Name}, "bytes": {strconv.FormatInt(v.Bytes, 10)}}
		if v.TargetDatabaseID != "" {
			q.Set("target_database_id", v.TargetDatabaseID)
			q.Set("target_revision", strconv.FormatInt(v.TargetRevision, 10))
		}
		req, e := http.NewRequestWithContext(r.Context(), "POST", "http://executor/v1/databases/imports/"+v.ID+"/upload?"+q.Encode(), http.MaxBytesReader(w, r.Body, MaxSQLImport))
		if e != nil {
			fail(w, 500, "无法准备传输")
			return
		}
		req.ContentLength = v.Bytes
		client := &http.Client{Transport: a.Executor.Client.Transport, Timeout: 30 * time.Minute}
		resp, e := client.Do(req)
		if e != nil {
			fail(w, 502, "上传中断；可用同一上传记录重传")
			return
		}
		defer resp.Body.Close()
		var out struct {
			DatabaseImport
			Error string `json:"error"`
		}
		if e = json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&out); e != nil {
			fail(w, 502, "无法核对上传结果")
			return
		}
		if resp.StatusCode != 200 {
			fail(w, 409, out.Error)
			return
		}
		if !ValidDatabaseImport(out.DatabaseImport, true) || out.ID != v.ID || out.ServerID != v.ServerID || out.Name != v.Name || out.Bytes != v.Bytes || out.TargetDatabaseID != v.TargetDatabaseID || out.TargetRevision != v.TargetRevision {
			fail(w, 502, "上传结果归属不符")
			return
		}
		_, e = a.Store.DB.Exec(`UPDATE mysql_imports SET sha256=?,state='staged' WHERE id=? AND state='awaiting_upload'`, out.SHA256, v.ID)
		if e != nil {
			fail(w, 500, "保存上传结果失败，可重传同一文件")
			return
		}
		_ = a.Store.Audit(u.Username, "mysql.import.upload", v.ID, "success")
		v, _ = a.Store.DatabaseImport(v.ID)
		send(w, 200, v)
	}))
	m.HandleFunc("POST /api/databases/imports/{id}/start", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.DatabaseImport(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "导入记录不存在")
			return
		}
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.ConfirmName != v.Name {
			fail(w, 400, "请输入目标数据库名确认")
			return
		}
		server, e := a.Store.DatabaseServer(v.ServerID)
		if e != nil {
			fail(w, 404, "实例不存在")
			return
		}
		if v.TargetDatabaseID != "" {
			d, e := a.Store.Database(v.TargetDatabaseID)
			if e != nil {
				fail(w, 409, "覆盖目标不存在")
				return
			}
			if v.State == "staged" {
				if _, e = a.databaseOverwritePlan(r, d); e != nil {
					fail(w, 409, e.Error())
					return
				}
			}
			d.Revision = v.TargetRevision
			a.queueDatabase(w, r, u, DatabaseOperation{Action: "overwrite_database", Server: server, Database: d, Import: &v})
			return
		}
		a.queueDatabase(w, r, u, DatabaseOperation{Action: "import_database", Server: server, Database: Database{Name: v.Name}, Import: &v})
	}))
}
