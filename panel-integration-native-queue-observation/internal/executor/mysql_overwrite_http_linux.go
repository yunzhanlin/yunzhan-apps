//go:build linux

package executor

import (
	"local/panel/internal/core"
	"net/http"
	"strconv"
)

func mysqlOverwriteRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/databases/overwrite-plan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerID   string `json:"server_id"`
			DatabaseID string `json:"database_id"`
			Revision   int64  `json:"revision"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		m, e := readMySQL(in.ServerID)
		if e != nil || !m.Ready {
			respond(w, 409, map[string]string{"error": "目标实例不可用"})
			return
		}
		d, e := readLifecycleDatabase(m.Server, in.DatabaseID)
		if e != nil || d.Revision != in.Revision || d.Status != "ready" {
			respond(w, 409, map[string]string{"error": "目标数据库身份或修订已变化"})
			return
		}
		op := core.DatabaseOperation{Action: "overwrite_database", JobID: core.ID(), Server: m.Server, PreviousDatabase: &d, Database: d}
		op.Database.Revision++
		op.Database.LastJobID = op.JobID
		op.Import = &core.DatabaseImport{ID: core.ID(), ServerID: m.Server.ID, Name: d.Name, TargetDatabaseID: d.ID, TargetRevision: d.Revision, Bytes: 1, SHA256: core.Hash("preflight")}
		j, e := inspectOverwriteTarget(r.Context(), op, false)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		raw, e := mysqlQuery(r.Context(), m.Server, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='"+d.Username+"';\n")
		if e != nil {
			respond(w, 409, map[string]string{"error": "无法核对目标应用连接"})
			return
		}
		count, e := strconv.Atoi(raw)
		if e != nil {
			respond(w, 409, map[string]string{"error": "连接数无法解析"})
			return
		}
		respond(w, 200, core.DatabaseOverwritePlan{DatabaseID: d.ID, Revision: d.Revision, Charset: j.Charset, Collation: j.Collation, Connections: count})
	})
}
