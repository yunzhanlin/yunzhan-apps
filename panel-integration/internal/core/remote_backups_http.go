package core

import (
	"context"
	"net/http"
	"time"
)

func (a *Server) remoteBackupRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/backups/remotes", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.BackupRemotes()
		if e != nil {
			fail(w, 500, "读取远端存储失败")
			return
		}
		send(w, 200, map[string]any{"remotes": items})
	}))
	m.HandleFunc("POST /api/backups/remotes", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in BackupRemoteInput
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.SaveBackupRemote("", in, u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, v)
	}))
	m.HandleFunc("PUT /api/backups/remotes/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in BackupRemoteInput
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.SaveBackupRemote(r.PathValue("id"), in, u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, v)
	}))
	m.HandleFunc("DELETE /api/backups/remotes/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		var count int
		if e := a.Store.DB.QueryRow(`SELECT (SELECT count(*) FROM backup_remote_copies WHERE remote_id=?)+(SELECT count(*) FROM mariadb_remote_copies WHERE remote_id=?)`, id, id).Scan(&count); e != nil || count > 0 {
			fail(w, 409, "远端存储已有传输记录，请停用后保留审计历史")
			return
		}
		result, e := a.Store.DB.Exec(`DELETE FROM backup_remotes WHERE id=?`, id)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			fail(w, 404, "远端存储不存在")
			return
		}
		_ = a.Store.Audit(u.Username, "backup.remote.delete", id, "success")
		send(w, 200, map[string]bool{"deleted": true})
	}))
	m.HandleFunc("POST /api/backups/remotes/{id}/test", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		remote, e := a.Store.BackupRemote(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "远端存储不存在")
			return
		}
		password, e := a.Store.backupRemotePassword(remote.ID)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		var result RemoteConnectionResult
		e = a.Executor.Call(ctx, http.MethodPost, "/v1/remote-backups/test", RemoteConnectionRequest{Remote: remote, Password: password}, &result)
		if e != nil {
			_ = a.Store.RecordRemoteTest(remote.ID, e.Error(), false)
			_ = a.Store.Audit(u.Username, "backup.remote.test", remote.ID, "failed")
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.RecordRemoteTest(remote.ID, "", true)
		_ = a.Store.Audit(u.Username, "backup.remote.test", remote.ID, "success")
		send(w, 200, result)
	}))
	m.HandleFunc("POST /api/backups/{kind}/{id}/remotes/{remote}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		copy, e := a.Store.QueueRemoteCopy(r.PathValue("remote"), r.PathValue("kind"), r.PathValue("id"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, copy)
	}))
	m.HandleFunc("GET /api/backups/remote-copies", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.RemoteCopies()
		if e != nil {
			fail(w, 500, "读取远端传输记录失败")
			return
		}
		send(w, 200, map[string]any{"copies": items})
	}))
}
