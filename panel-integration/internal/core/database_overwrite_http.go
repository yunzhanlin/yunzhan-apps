package core

import (
	"errors"
	"net/http"
)

type DatabaseOverwritePlan struct {
	DatabaseID  string `json:"database_id"`
	Revision    int64  `json:"revision"`
	Charset     string `json:"charset"`
	Collation   string `json:"collation"`
	Connections int    `json:"connections"`
}

func (a *Server) databaseOverwritePlan(r *http.Request, d Database) (DatabaseOverwritePlan, error) {
	var plan DatabaseOverwritePlan
	if d.Status != "ready" {
		return plan, errors.New("目标数据库当前不可用，请先完成原任务")
	}
	refs, e := databaseAccountReferences(a.Store.DB, d.ID)
	if e != nil {
		return plan, e
	}
	for _, ref := range refs {
		if ref.Status != "quarantined" {
			return plan, errors.New("请先回收引用此库的独立账号或解除其授权")
		}
	}
	if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/overwrite-plan", map[string]any{"server_id": d.ServerID, "database_id": d.ID, "revision": d.Revision}, &plan); e != nil {
		return plan, e
	}
	if plan.DatabaseID != d.ID || plan.Revision != d.Revision {
		return plan, errors.New("覆盖预检的目标修订不一致")
	}
	return plan, nil
}
func (a *Server) databaseOverwriteRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/databases/items/{id}/overwrite-plan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		d, e := a.Store.Database(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库不存在")
			return
		}
		plan, e := a.databaseOverwritePlan(r, d)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, plan)
	}))
	m.HandleFunc("POST /api/databases/items/{id}/overwrite-upload", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Bytes    int64 `json:"bytes"`
			Revision int64 `json:"revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		d, e := a.Store.Database(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库不存在")
			return
		}
		if d.Revision != in.Revision {
			fail(w, 409, "目标修订已变化，请重新核对")
			return
		}
		if _, e = a.databaseOverwritePlan(r, d); e != nil {
			fail(w, 409, e.Error())
			return
		}
		v, e := a.Store.PrepareDatabaseImport(DatabaseImport{ServerID: d.ServerID, Name: d.Name, Bytes: in.Bytes, TargetDatabaseID: d.ID, TargetRevision: d.Revision}, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, v)
	}))
}
