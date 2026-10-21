package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type WAFEngineStatus struct {
	JobID             string `json:"job_id"`
	State             string `json:"state"`
	Error             string `json:"error,omitempty"`
	Architecture      string `json:"architecture"`
	Engine            string `json:"engine_version"`
	CRS               string `json:"crs_version"`
	NginxVersion      string `json:"nginx_version"`
	StartedAt         string `json:"started_at,omitempty"`
	FinishedAt        string `json:"finished_at,omitempty"`
	Steps             []Step `json:"steps"`
	ABIValidated      bool   `json:"module_abi_validated"`
	IntegrityVerified bool   `json:"integrity_verified"`
	BuildOnly         bool   `json:"build_only"`
}

func (s *Store) updateWAFEngineSteps(id string, steps []Step) error {
	b, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`UPDATE runtime_jobs SET steps=?,updated_at=? WHERE id=? AND kind='waf_engine_build' AND target_id='nginx-waf' AND state IN ('queued','running')`, string(b), Now(), id)
	return err
}

func (s *Store) QueueWAFEngineBuild(key, actor string) (string, error) {
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
		if target != "nginx-waf" || kind != "waf_engine_build" {
			return "", errors.New("幂等键已被不同请求使用")
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	id = ID()
	if _, err = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,'nginx-waf','waf_engine_build','queued',?,?,?)`, id, key, Now(), Now()); err != nil {
		return "", errors.New("防火墙已有正在执行的操作；不会并行修改或重复构建")
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.engine.build',?,'queued',?)`, actor, id, Now()); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (a *Server) wafEngineRoutes(m *http.ServeMux) {
	admin := func(w http.ResponseWriter, u identity) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "原生防火墙引擎仅管理员可管理")
			return false
		}
		return true
	}
	m.HandleFunc("POST /api/software/nginx-waf/engine/build", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(w, u) {
			return
		}
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		id, err := a.Store.QueueWAFEngineBuild(r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))
	m.HandleFunc("POST /api/software/nginx-waf/engine/jobs/{id}/cancel", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
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
		if err := a.Store.DB.QueryRowContext(r.Context(), `SELECT state FROM runtime_jobs WHERE id=? AND target_id='nginx-waf' AND kind='waf_engine_build'`, id).Scan(&state); err != nil {
			fail(w, 409, "只能停止本面板创建的原生 WAF 构建任务")
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
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/engine/jobs/"+id+"/cancel", struct{}{}, &out); err != nil {
			fail(w, 503, "不能确认构建已停止；未宣称取消成功："+err.Error())
			return
		}
		if out.JobID != id || !out.BuildOnly || (out.State != "failed" && out.State != "ready") {
			fail(w, 503, "停止构建响应无法核实，保留原任务")
			return
		}
		if out.State == "failed" {
			if err := a.Store.FinishRuntime(Job{ID: id, TargetID: "nginx-waf", Kind: "waf_engine_build"}, out.Error, out.Steps); err != nil {
				fail(w, 503, "构建已停止，但持久任务状态需核对")
				return
			}
		}
		_ = a.Store.Audit(u.Username, "waf.engine.cancel", id, out.State)
		send(w, 200, out)
	}))
	for _, operation := range []string{"engines", "engine/jobs/{id}"} {
		m.HandleFunc("GET /api/software/nginx-waf/"+operation, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			if !admin(w, u) {
				return
			}
			endpoint := "/v1/software/nginx-waf/engines"
			if operation != "engines" {
				if !ValidID(r.PathValue("id")) {
					fail(w, 400, "引擎任务标识无效")
					return
				}
				endpoint = "/v1/software/nginx-waf/engine/jobs/" + r.PathValue("id")
				var state, detail, steps string
				err := a.Store.DB.QueryRowContext(r.Context(), `SELECT state,error,steps FROM runtime_jobs WHERE id=? AND target_id='nginx-waf' AND kind='waf_engine_build'`, r.PathValue("id")).Scan(&state, &detail, &steps)
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
