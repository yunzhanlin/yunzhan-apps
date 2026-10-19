package core

import "net/http"

// This handler only reads one original project. It does not pull a catalog,
// reserve an idempotency key, enqueue a job, update a receipt or start Docker.
func (a *Server) memcachedRegistryPlanRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-registry/{id}/instances/{project}/update-plan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		project := r.PathValue("project")
		if r.PathValue("id") != "memcached" || !ValidID(project) {
			fail(w, 404, "不支持的应用或原项目身份")
			return
		}
		if a.Executor == nil {
			fail(w, 503, "原项目状态暂不可确认")
			return
		}
		var plan MemcachedUpdatePlan
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/projects/"+project+"/app-update-plan", nil, &plan); err != nil || ValidateMemcachedUpdatePlan(plan, project) != nil {
			fail(w, 409, "原 Memcached 项目预检未通过；保留原配置，未提交更新")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		send(w, 200, plan)
	}))
}
