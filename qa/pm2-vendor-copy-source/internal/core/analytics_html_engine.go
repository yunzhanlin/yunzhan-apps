package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (s *Store) updateAnalyticsHTMLSteps(id string, steps []Step) error {
	b, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`UPDATE runtime_jobs SET steps=?,updated_at=? WHERE id=? AND kind='analytics_html_build' AND target_id='website-analytics' AND state IN ('queued','running')`, string(b), Now(), id)
	return err
}

func (s *Store) QueueAnalyticsHTMLBuild(key, actor string) (string, error) {
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效的幂等键")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id, target, kind string
	err = tx.QueryRow(`SELECT id,target_id,kind FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id, &target, &kind)
	if err == nil {
		if target != "website-analytics" || kind != "analytics_html_build" {
			return "", errors.New("幂等键已被不同请求使用")
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var retained int
	if err := tx.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id='website-analytics' AND kind='analytics_html_build'`).Scan(&retained); err != nil {
		return "", err
	}
	if retained >= 64 {
		return "", errors.New("HTML 构建记录已达 64 份，原任务与证据保留，不自动删除或覆盖")
	}
	id = ID()
	if _, err = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,'website-analytics','analytics_html_build','queued',?,?,?)`, id, key, Now(), Now()); err != nil {
		return "", errors.New("网站分析已有正在执行的操作；不会并行修改或重复构建")
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'analytics.html.build',?,'queued',?)`, actor, id, Now()); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (a *Server) analyticsHTMLEngineRoutes(m *http.ServeMux) {
	admin := func(w http.ResponseWriter, u identity) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "HTML 自动接入引擎仅管理员可管理")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/website-analytics/html-engine/active", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		var out struct {
			Active       *bool  `json:"active"`
			State        string `json:"state"`
			JobID        string `json:"job_id,omitempty"`
			Acknowledged bool   `json:"worker_acknowledged,omitempty"`
			Error        string `json:"error,omitempty"`
		}
		if err := a.Executor.Call(r.Context(), "GET", "/v1/software/website-analytics/html-engine/active", nil, &out); err != nil {
			fail(w, 503, err.Error())
			return
		}
		if out.Active == nil || (*out.Active && (out.State != "active" || !ValidID(out.JobID) || !out.Acknowledged || out.Error != "")) ||
			(!*out.Active && (out.State != "not-activated" && out.State != "needs-attention" || out.Acknowledged || out.JobID != "")) {
			fail(w, 503, "HTML 引擎实际状态无法核实，未宣称已加载或未加载")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/website-analytics/html-engine/activate", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		var in struct {
			JobID string `json:"job_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !ValidID(in.JobID) {
			fail(w, 400, "HTML 引擎构建标识无效")
			return
		}
		var state string
		if err := a.Store.DB.QueryRowContext(r.Context(), `SELECT state FROM runtime_jobs WHERE id=? AND target_id='website-analytics' AND kind='analytics_html_build'`, in.JobID).Scan(&state); err != nil || state != "succeeded" {
			fail(w, 409, "只能加载本面板已成功且核验完成的 HTML 构建")
			return
		}
		var out struct {
			JobID         string `json:"job_id"`
			Active        bool   `json:"active"`
			Acknowledged  bool   `json:"worker_acknowledged"`
			SiteInjection *bool  `json:"site_auto_injection"`
		}
		if err := a.Executor.Call(r.Context(), "POST", "/v1/software/website-analytics/html-engine/activate", in, &out); err != nil {
			fail(w, 503, err.Error())
			return
		}
		if out.JobID != in.JobID || !out.Active || !out.Acknowledged || out.SiteInjection == nil || *out.SiteInjection {
			fail(w, 503, "HTML 引擎加载或工作进程确认无法核实，未宣称成功")
			return
		}
		if err := a.Store.Audit(u.Username, "analytics.html.activate", in.JobID, "worker-acknowledged"); err != nil {
			fail(w, 503, "引擎可能已加载，但审计保存失败，请刷新核对")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/website-analytics/html-engine/build", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		id, err := a.Store.QueueAnalyticsHTMLBuild(r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))
	m.HandleFunc("POST /api/software/website-analytics/html-engine/jobs/{id}/cancel", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "引擎任务标识无效")
			return
		}
		var state string
		if err := a.Store.DB.QueryRowContext(r.Context(), `SELECT state FROM runtime_jobs WHERE id=? AND target_id='website-analytics' AND kind='analytics_html_build'`, id).Scan(&state); err != nil {
			fail(w, 409, "只能停止本面板创建的HTML 构建任务")
			return
		}
		if state != "queued" && state != "running" {
			send(w, 200, map[string]string{"job_id": id, "state": state})
			return
		}
		// The restricted executor stores a durable cancellation barrier even
		// before dispatch, closing the queue-claim/dependency/start race.
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		var out WAFEngineStatus
		if err := a.Executor.Call(ctx, "POST", "/v1/software/website-analytics/html-engine/jobs/"+id+"/cancel", struct{}{}, &out); err != nil {
			fail(w, 503, "不能确认构建已停止；未宣称取消成功："+err.Error())
			return
		}
		if out.JobID != id || !out.BuildOnly || (out.State != "failed" && out.State != "ready") {
			fail(w, 503, "停止构建响应无法核实，保留原任务")
			return
		}
		if out.State == "failed" {
			if err := a.Store.FinishRuntime(Job{ID: id, TargetID: "website-analytics", Kind: "analytics_html_build"}, out.Error, out.Steps); err != nil {
				fail(w, 503, "构建已停止，但持久任务状态需核对")
				return
			}
		}
		_ = a.Store.Audit(u.Username, "analytics.html.cancel", id, out.State)
		send(w, 200, out)
	}))
	for _, operation := range []string{"html-engines", "html-engine/jobs/{id}"} {
		m.HandleFunc("GET /api/software/website-analytics/"+operation, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			if !admin(w, u) {
				return
			}
			endpoint := "/v1/software/website-analytics/html-engines"
			if operation == "html-engines" {
				var out struct {
					Entries   []WAFEngineStatus `json:"entries"`
					BuildOnly bool              `json:"build_only"`
				}
				if err := a.Executor.Call(r.Context(), "GET", endpoint, nil, &out); err != nil {
					fail(w, 503, err.Error())
					return
				}
				if !out.BuildOnly || out.Entries == nil || len(out.Entries) > 192 {
					fail(w, 503, "HTML 原生构建库存不完整，未当作空列表")
					return
				}
				entries, err := a.Store.mergeAnalyticsHTMLInventory(r.Context(), out.Entries)
				if err != nil {
					fail(w, 503, err.Error())
					return
				}
				send(w, 200, map[string]any{"entries": entries, "build_only": true, "activation_requires_explicit_site_policy": true})
				return
			}
			if operation != "html-engines" {
				if !ValidID(r.PathValue("id")) {
					fail(w, 400, "引擎任务标识无效")
					return
				}
				endpoint = "/v1/software/website-analytics/html-engine/jobs/" + r.PathValue("id")
				var state, detail, steps string
				err := a.Store.DB.QueryRowContext(r.Context(), `SELECT state,error,steps FROM runtime_jobs WHERE id=? AND target_id='website-analytics' AND kind='analytics_html_build'`, r.PathValue("id")).Scan(&state, &detail, &steps)
				if err == nil && state != "succeeded" {
					out := WAFEngineStatus{JobID: r.PathValue("id"), State: state, Error: detail, BuildOnly: true, Steps: []Step{}}
					if json.Unmarshal([]byte(steps), &out.Steps) != nil {
						fail(w, 503, "持久构建步骤损坏")
						return
					}
					send(w, 200, out)
					return
				} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
					fail(w, 503, "不能读取持久构建状态")
					return
				}
			}
			var out any
			if err := a.Executor.Call(r.Context(), "GET", endpoint, nil, &out); err != nil {
				fail(w, 503, err.Error())
				return
			}
			send(w, 200, out)
		}))
	}
}
