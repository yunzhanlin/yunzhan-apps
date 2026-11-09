package core

import (
	"net/http"
)

// Nest these routes under a website so the existing role/site scope applies to
// inventory, mutations and logs alike. The executor repeats the ownership check.
func (a *Server) phpWorkerRoutes(m *http.ServeMux) {
	base := "/api/sites/{id}/php-workers"
	m.HandleFunc("GET "+base+"/operations/{operation}/status", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) || !ValidID(r.PathValue("operation")) {
			fail(w, 400, "PHP 进程操作标识无效")
			return
		}
		var out PHPWorkerOperation
		if e := a.Executor.Call(r.Context(), "GET", "/v1/sites/"+r.PathValue("id")+"/php-workers/operations/"+r.PathValue("operation")+"/status", nil, &out); e != nil {
			fail(w, 404, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "网站不存在")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/sites/"+r.PathValue("id")+"/php-workers", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in PHPWorkerSpec
		if !decode(w, r, &in) {
			return
		}
		in.SiteID = r.PathValue("id")
		if e := ValidatePHPWorkerSpec(in); e != nil {
			fail(w, 400, e.Error())
			return
		}
		site, e := a.Store.Site(in.SiteID)
		if e != nil || site.Status != "running" || site.PHPVersionID == "" {
			fail(w, 409, "请先启动已绑定 PHP 的网站")
			return
		}
		worker := PHPWorker{PHPWorkerSpec: in, ID: ID(), UpdatedAt: Now(), ObservedReleaseID: site.PHPVersionID}
		var out PHPWorkerOperation
		if e = a.Executor.Call(r.Context(), "POST", "/v1/sites/"+in.SiteID+"/php-workers", worker, &out); e != nil {
			_ = a.Store.Audit(u.Username, "php.worker.create", in.Name, "failed")
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "php.worker.create", in.Name+" · "+out.ID, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("POST "+base+"/{worker}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, worker, action := r.PathValue("id"), r.PathValue("worker"), r.PathValue("action")
		if !ValidID(id) || !ValidID(worker) || (action != "start" && action != "stop" && action != "restart") {
			fail(w, 400, "PHP 进程操作无效")
			return
		}
		var out PHPWorkerOperation
		if e := a.Executor.Call(r.Context(), "POST", "/v1/sites/"+id+"/php-workers/"+worker+"/"+action, map[string]any{}, &out); e != nil {
			_ = a.Store.Audit(u.Username, "php.worker."+action, worker, "failed")
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "php.worker."+action, worker+" · "+out.ID, "queued")
		send(w, 202, out)
	}))
	m.HandleFunc("GET "+base+"/{worker}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) || !ValidID(r.PathValue("worker")) {
			fail(w, 400, "PHP 进程标识无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/sites/"+r.PathValue("id")+"/php-workers/"+r.PathValue("worker")+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE "+base+"/{worker}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !ValidID(r.PathValue("id")) || !ValidID(r.PathValue("worker")) || !nodeAppName.MatchString(in.ConfirmName) {
			fail(w, 400, "PHP 进程删除确认无效")
			return
		}
		var out PHPWorkerOperation
		if e := a.Executor.Call(r.Context(), "DELETE", "/v1/sites/"+r.PathValue("id")+"/php-workers/"+r.PathValue("worker"), in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "php.worker.delete", in.ConfirmName+" · "+out.ID, "queued")
		send(w, 202, out)
	}))
}
