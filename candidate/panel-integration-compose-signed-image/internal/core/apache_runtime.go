package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"local/panel/internal/runtimecatalog"
)

type ApacheRuntimeSelection struct {
	ReleaseID   string `json:"release_id"`
	EngineJobID string `json:"engine_job_id"`
}
type ApacheRuntimeDispatch struct {
	ApacheRuntimeSelection
	JobID          string `json:"job_id"`
	ActorID        string `json:"actor_id"`
	AccessRevision int64  `json:"access_revision"`
}

func (s *Store) QueueApacheRuntime(ctx context.Context, in ApacheRuntimeSelection, key, actor string) (string, error) {
	if !ValidID(key) || in.ReleaseID != runtimecatalog.ApacheCurrentID || in.EngineJobID != "" && !ValidID(in.EngineJobID) {
		return "", errors.New("请选择已审核 Apache 目标与有效原请求标识")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	access, err := readUserAccessContext(ctx, tx, actor)
	if err != nil || !ValidID(actor) || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 {
		return "", errors.New("Apache 全局版本切换需要当前完整管理员")
	}
	var priorID, target, kind, payload string
	err = tx.QueryRowContext(ctx, `SELECT id,target_id,kind,payload FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&priorID, &target, &kind, &payload)
	if err == nil {
		var prior ApacheRuntimeDispatch
		if json.Unmarshal([]byte(payload), &prior) != nil || prior.JobID != priorID || target != in.ReleaseID || kind != "switch_apache" || prior.ApacheRuntimeSelection != in || prior.ActorID != actor || prior.AccessRevision != access.Revision {
			return "", errors.New("原请求标识已用于不同操作、账户或权限修订")
		}
		return priorID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM runtime_installations WHERE id=? AND status='installed'`, in.ReleaseID).Scan(&n); err != nil || n != 1 {
		return "", errors.New("先安装并核对目标 Apache，安装不会自动切换网站")
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM runtime_jobs WHERE (kind='switch_apache' OR target_id IN ('apache-2.4.68','apache-2.4.71','apache-waf')) AND state IN ('queued','running','needs_attention')`).Scan(&n); err != nil || n != 0 {
		return "", errors.New("已有 Apache 相关操作待完成或待核对")
	}
	id := ID()
	request := ApacheRuntimeDispatch{in, id, actor, access.Revision}
	raw, _ := json.Marshal(request)
	if _, err = tx.ExecContext(ctx, `INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,payload,created_at,updated_at) VALUES(?,?,'switch_apache','queued',?,?,?,?)`, id, in.ReleaseID, key, string(raw), Now(), Now()); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'apache.runtime.switch',?,'queued',?)`, actor, in.ReleaseID, Now()); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (s *Store) apacheRuntimeDispatch(ctx context.Context, j Job) (ApacheRuntimeDispatch, error) {
	var request ApacheRuntimeDispatch
	if len(j.Payload) > 2048 || json.Unmarshal([]byte(j.Payload), &request) != nil || request.JobID != j.ID || request.ReleaseID != j.TargetID || request.ReleaseID != runtimecatalog.ApacheCurrentID || j.Kind != "switch_apache" || !ValidID(request.ActorID) || request.AccessRevision < 1 || request.EngineJobID != "" && !ValidID(request.EngineJobID) {
		return request, errors.New("Apache 原切换请求不完整，未执行")
	}
	access, err := s.UserAccess(request.ActorID)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision != request.AccessRevision {
		return request, errors.New("原 Apache 操作者或权限修订已变化，未执行")
	}
	var raw, state string
	if err := s.DB.QueryRowContext(ctx, `SELECT payload,state FROM runtime_jobs WHERE id=? AND kind='switch_apache' AND target_id=?`, j.ID, j.TargetID).Scan(&raw, &state); err != nil || raw != j.Payload || state != "running" {
		return request, errors.New("Apache 原任务已变化，未执行")
	}
	return request, nil
}

func (a *Server) apacheRuntimeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/runtimes/apache", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var result map[string]any
		if err := a.Executor.Call(r.Context(), "GET", "/v1/apache/runtime", nil, &result); err != nil {
			fail(w, 503, err.Error())
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("POST /api/runtimes/apache/switch", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in ApacheRuntimeSelection
		if !decode(w, r, &in) {
			return
		}
		id, err := a.Store.QueueApacheRuntime(r.Context(), in, r.Header.Get("Idempotency-Key"), u.ID)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))
}

// A read of the original Root receipt never reissues POST or restarts a service.
func (s *Store) observeApacheRuntimeCompletion(ctx context.Context, e *ExecutorClient, j Job) (ApplyResult, string, bool) {
	var observed struct {
		JobID   string                `json:"job_id"`
		State   string                `json:"state"`
		Request ApacheRuntimeDispatch `json:"request"`
		Result  ApplyResult           `json:"result"`
		Error   string                `json:"error"`
	}
	if err := e.Call(ctx, "GET", "/v1/apache/runtime/jobs/"+j.ID, nil, &observed); err != nil || observed.JobID != j.ID {
		return ApplyResult{}, "Apache 原生回执暂不可核实，未重新提交", false
	}
	if observed.State == "missing" {
		return ApplyResult{}, "Apache 原请求未进入原生配置事务，未重新提交", true
	}
	var request ApacheRuntimeDispatch
	if json.Unmarshal([]byte(j.Payload), &request) != nil || observed.Request != request || len(observed.Result.Steps) > 64 {
		return ApplyResult{}, "Apache 原生回执身份不一致，未推断完成", false
	}
	if observed.State == "committed" && observed.Error == "" && (observed.Result.Status == "running" || observed.Result.Status == "unchanged") {
		return observed.Result, "", true
	}
	if observed.State == "failed" && observed.Error != "" && (observed.Result.Status == "restored" || observed.Result.Status == "unchanged") {
		return observed.Result, observed.Error, true
	}
	return observed.Result, "Apache 原请求没有明确提交或恢复完成回执，证据保留，未重新提交", false
}
