package core

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type SystemBackup struct {
	ID        string `json:"id"`
	Format    string `json:"format"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Files     int    `json:"files"`
	Schema    int    `json:"schema"`
	Arch      string `json:"arch"`
	CreatedAt string `json:"created_at"`
}
type SystemBackupCreateRequest struct {
	ID         string `json:"id"`
	Passphrase string `json:"passphrase"`
}
type SystemBackupRestoreRequest struct {
	Passphrase  string `json:"passphrase"`
	Destination string `json:"destination"`
}

func (s *Store) migrateSystemBackups() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS system_backups(id TEXT PRIMARY KEY,format TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,files INTEGER NOT NULL,schema_version INTEGER NOT NULL,architecture TEXT NOT NULL,created_at TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(21,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func (s *Store) SystemBackups() ([]SystemBackup, error) {
	rows, e := s.DB.Query(`SELECT id,format,bytes,sha256,files,schema_version,architecture,created_at FROM system_backups ORDER BY created_at DESC,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SystemBackup{}
	for rows.Next() {
		var v SystemBackup
		if e = rows.Scan(&v.ID, &v.Format, &v.Bytes, &v.SHA256, &v.Files, &v.Schema, &v.Arch, &v.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SystemBackup(id string) (SystemBackup, error) {
	var v SystemBackup
	e := s.DB.QueryRow(`SELECT id,format,bytes,sha256,files,schema_version,architecture,created_at FROM system_backups WHERE id=?`, id).Scan(&v.ID, &v.Format, &v.Bytes, &v.SHA256, &v.Files, &v.Schema, &v.Arch, &v.CreatedAt)
	return v, e
}
func (s *Store) RecordSystemBackup(v SystemBackup, actor string) error {
	if !ValidID(v.ID) || v.Format != "panel-backup-v1" || v.Bytes < 1 || len(v.SHA256) != 64 || v.Files < 2 || v.Schema < 1 {
		return errors.New("系统备份结果无效")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO system_backups VALUES(?,?,?,?,?,?,?,?)`, v.ID, v.Format, v.Bytes, v.SHA256, v.Files, v.Schema, v.Arch, v.CreatedAt); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'system.backup.create',?,'success',?)`, actor, v.ID, Now()); e != nil {
		return e
	}
	return tx.Commit()
}

func (a *Server) systemBackupRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/backups/system", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.SystemBackups()
		if e != nil {
			fail(w, 500, "读取面板整包备份失败")
			return
		}
		send(w, 200, map[string]any{"backups": items})
	}))
	m.HandleFunc("POST /api/backups/system", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in SystemBackupCreateRequest
		if !decode(w, r, &in) {
			return
		}
		if len(in.Passphrase) < 12 || len(in.Passphrase) > 256 {
			fail(w, 409, "备份密码应为 12–256 个字符")
			return
		}
		in.ID = ID()
		var result SystemBackup
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/system-backups/create", in, &result); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if e := a.Store.RecordSystemBackup(result, u.Username); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, result)
	}))
	m.HandleFunc("GET /api/backups/system/{id}/download", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.SystemBackup(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "面板整包备份不存在")
			return
		}
		q := url.Values{"bytes": {strconv.FormatInt(v.Bytes, 10)}, "sha256": {v.SHA256}}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		sent, e := a.proxyStream(w, r, "/v1/system-backups/"+v.ID+"/download?"+q.Encode(), 30*time.Minute)
		result := "success"
		if e != nil {
			result = "failed"
			if !sent {
				fail(w, 502, e.Error())
			}
		}
		_ = a.Store.Audit(u.Username, "system.backup.download", v.ID, result)
	}))
}
