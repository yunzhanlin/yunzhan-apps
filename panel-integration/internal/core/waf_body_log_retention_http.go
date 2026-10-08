package core

import (
	"context"
	"net/http"
	"time"
)

func (a *Server) wafBodyRetentionRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/software/nginx-waf/body-log/retention/retain", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可核对自动清理未知结果")
			return
		}
		var in WAFBodyLogRetentionRetainRequest
		if !decode(w, r, &in) {
			return
		}
		if !in.Valid() || len(r.URL.Query()) != 0 {
			fail(w, 400, "自动清理摘要或未知结果确认无效")
			return
		}
		if err := a.Store.Audit(u.Username, "waf.body-log.retention-review-requested", "nginx-waf", "digest="+in.SHA256+"; acknowledge unknown deletion; never retry original plan"); err != nil {
			fail(w, 500, "无法保存核对请求审计；尚未操作")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out any
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/body-log/retention/retain", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if err := a.Store.Audit(u.Username, "waf.body-log.retention-unknown-retained", "nginx-waf", "digest="+in.SHA256+"; unknown plan preserved, not successful; no archive or current log deleted"); err != nil {
			fail(w, 503, "执行器已保存核对记录，但面板结果审计保存失败；请刷新状态，勿重复原删除计划")
			return
		}
		send(w, 200, out)
	}))
}
