package core

import (
	"database/sql"
	"errors"
	"local/panel/internal/runtimecatalog"
	"net/http"
)

type RuntimeReference struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

func (s *Store) RuntimeReferences(release string) ([]RuntimeReference, error) {
	return queryRuntimeReferences(s.DB, release)
}
func queryRuntimeReferences(db interface {
	Query(string, ...any) (*sql.Rows, error)
}, release string) ([]RuntimeReference, error) {
	if _, ok := runtimecatalog.Find(release); !ok && release != "nginx-system" {
		return nil, errors.New("版本不在受管目录中")
	}
	rows, e := db.Query(`
 SELECT 'site',id,name,status FROM sites WHERE php_version_id=?
 UNION ALL SELECT 'mysql_instance',id,name,status FROM mysql_servers WHERE release_id=?
 UNION ALL SELECT 'nginx_ingress',id,name,'selected' FROM runtime_instances WHERE id='nginx-ingress' AND installation_id=?
 UNION ALL SELECT 'apache_site',id,name,status FROM sites WHERE ?='apache-2.4.68' AND COALESCE(json_extract(settings_json,'$.web_server'),'nginx')='apache'
 UNION ALL SELECT 'site_job',j.id,s.name,j.state FROM jobs j JOIN sites s ON s.id=j.site_id WHERE j.state IN ('queued','running','needs_attention') AND json_extract(j.payload,'$.release_id')=?
 UNION ALL SELECT 'runtime_job',id,kind,state FROM runtime_jobs WHERE target_id=? AND state IN ('queued','running','needs_attention')
 ORDER BY 1,2`, release, release, release, release, release, release)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RuntimeReference{}
	for rows.Next() {
		var item RuntimeReference
		if e = rows.Scan(&item.Kind, &item.ID, &item.Name, &item.State); e != nil {
			return nil, e
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
func (a *Server) runtimeReferenceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/runtimes/{id}/references", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		recorded, e := a.Store.RuntimeReferences(id)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		var actual []RuntimeReference
		if e = a.Executor.Call(r.Context(), "GET", "/v1/runtimes/references/"+id, nil, &actual); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, map[string]any{"release_id": id, "recorded": recorded, "actual": actual, "checked_at": Now(), "referenced": len(recorded)+len(actual) > 0})
	}))
}
