package core

import (
	"database/sql"
	"errors"
	"net/http"
)

// This deliberately omits payload, steps and unrelated site/database fields.
// WAF users need only their authorized software's exact install/configure
// outcome, not a grant to the entire audit/jobs API or a new executor command.
type wafApplyTaskStatus struct {
	ID       string `json:"id"`
	TargetID string `json:"target_id"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Error    string `json:"error"`
}

func (a *Server) wafApplyTaskRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/{id}/jobs/{job}", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		w.Header().Set("Cache-Control", "no-store")
		app, id := r.PathValue("id"), r.PathValue("job")
		if (app != "nginx-waf" && app != "apache-waf") || !ValidID(id) || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "防火墙任务标识或查询字段无效")
			return
		}
		var out wafApplyTaskStatus
		err := a.Store.DB.QueryRow(`SELECT id,target_id,kind,state,error FROM runtime_jobs WHERE id=? AND target_id=? AND kind IN ('software_install','software_configure')`, id, app).Scan(&out.ID, &out.TargetID, &out.Kind, &out.State, &out.Error)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "未找到该防火墙的原安装或配置任务；未重新提交")
			return
		}
		if err != nil {
			fail(w, 503, "原防火墙任务暂时不可读取；未重新提交")
			return
		}
		if !containsString([]string{"queued", "running", "succeeded", "failed", "needs_attention", "cancelled"}, out.State) || len(out.Error) > 32768 {
			fail(w, 409, "原防火墙任务状态不可核对；未宣称成功或重新提交")
			return
		}
		send(w, 200, out)
	}))
}
