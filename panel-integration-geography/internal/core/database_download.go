package core

import (
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (s *Store) DatabaseBackup(id string) (DatabaseBackup, error) {
	var b DatabaseBackup
	err := s.DB.QueryRow(`SELECT id,database_id,server_id,version,bytes,sha256,created_at FROM mysql_backups WHERE id=?`, id).Scan(&b.ID, &b.DatabaseID, &b.ServerID, &b.Version, &b.Bytes, &b.SHA256, &b.CreatedAt)
	return b, err
}
func (a *Server) databaseDownloadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/backups/{id}/download", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "备份标识无效")
			return
		}
		backup, err := a.Store.DatabaseBackup(id)
		if err != nil {
			fail(w, 404, "备份不存在")
			return
		}
		if _, err = a.Store.DatabaseServer(backup.ServerID); err != nil {
			fail(w, 409, "备份所属实例记录不可读取")
			return
		}
		values := url.Values{"database_id": {backup.DatabaseID}, "sha256": {backup.SHA256}, "bytes": {strconv.FormatInt(backup.Bytes, 10)}, "version": {backup.Version}}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		sent, err := a.proxyStream(w, r, "/v1/databases/backups/"+backup.ServerID+"/"+id+"/download?"+values.Encode(), 30*time.Minute)
		result := "success"
		if err != nil {
			result = "failed"
			if !sent {
				fail(w, 502, err.Error())
			}
		}
		_ = a.Store.Audit(u.Username, "mysql.backup.download", id, result)
	}))
}
