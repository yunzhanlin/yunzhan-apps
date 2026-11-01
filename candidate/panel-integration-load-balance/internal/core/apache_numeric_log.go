package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Only explicitly selected fixed-ID maintenance is forwarded. File paths,
// service controls and raw log bytes are never public parameters.
func (a *Server) apacheNumericLogRoutes(m *http.ServeMux) {
	for _, op := range []struct{ method, suffix, kind string }{
		{"GET", "archives", "inventory"}, {"GET", "archives/{id}", "export"},
		{"POST", "rotate", "rotate"}, {"POST", "archives/{id}/remove", "remove"},
		{"POST", "archives/{id}/retain", "retain"}, {"POST", "index-stages/{id}/retain", "retain-stage"},
	} {
		m.HandleFunc(op.method+" /api/software/apache-waf/body-log/"+op.suffix, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			role, _, err := a.Store.appUserRole(u.ID)
			if err != nil || role != "admin" {
				fail(w, 403, "Apache 数值日志维护仅管理员可访问")
				return
			}
			if len(r.URL.Query()) != 0 {
				fail(w, 400, "日志维护不接受查询参数或路径")
				return
			}
			suffix := op.suffix
			target := "apache-waf"
			if id := r.PathValue("id"); id != "" {
				if !ValidID(id) {
					fail(w, 400, "数值日志记录标识无效")
					return
				}
				target = id
				suffix = strings.ReplaceAll(suffix, "{id}", id)
			}
			var payload any
			if op.method == "POST" {
				raw, e := io.ReadAll(io.LimitReader(r.Body, 4097))
				if e != nil {
					fail(w, 400, "读取日志维护请求失败")
					return
				}
				in, e := DecodeApacheNumericLogMaintenance(raw, op.kind)
				if e != nil {
					fail(w, 400, e.Error())
					return
				}
				payload = in
				if err = a.Store.Audit(u.Username, "apache.body-log."+op.kind+".requested", target, "Explicit fixed-ID maintenance; unknown outcome must be observed, never automatically replayed"); err != nil {
					fail(w, 503, "日志维护请求审计未保存，未提交")
					return
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			var out json.RawMessage // Preserve inode/time evidence without float64 rounding.
			if err = a.Executor.Call(ctx, op.method, "/v1/software/apache-waf/body-log/"+suffix, payload, &out); err != nil {
				fail(w, 409, err.Error())
				return
			}
			if op.method == "POST" {
				if err = a.Store.Audit(u.Username, "apache.body-log."+op.kind+".completed", target, "Executor returned a confirmed maintenance receipt; current website configuration and service control were not changed"); err != nil {
					fail(w, 503, "执行器已返回回执，但完成审计未保存；请核对原记录，不要重复提交")
					return
				}
			}
			send(w, 200, out)
		}))
	}
}
