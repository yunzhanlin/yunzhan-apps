package core

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

type registryRequestOutcome struct {
	AppID      string `json:"app_id"`
	Action     string `json:"action"`
	JobID      string `json:"job_id"`
	Provider   string `json:"provider"`
	State      string `json:"state"`
	StateKnown bool   `json:"state_known"`
	Version    string `json:"version"`
	SHA256     string `json:"sha256"`
}

// This endpoint only observes a retained, actor-bound request. It never pulls
// the catalog, retries an executor command, modifies a receipt, or exposes input.
func (a *Server) registryRequestStatus(w http.ResponseWriter, r *http.Request, u identity) {
	app, key := r.PathValue("id"), r.PathValue("key")
	if validateRegistryUpdateRequest(app, u.ID, key, registryUpdateInput{"1.0.0", strings.Repeat("0", 64)}) != nil {
		fail(w, 400, "应用请求标识无效")
		return
	}
	var install, update, closed int
	if err := a.Store.DB.QueryRow(`SELECT (SELECT count(*) FROM app_registry_install_requests WHERE idempotency_key=?),(SELECT count(*) FROM app_registry_update_requests WHERE idempotency_key=?),(SELECT count(*) FROM app_registry_request_closures WHERE idempotency_key=?)`, key, key, key).Scan(&install, &update, &closed); err != nil || install+update+closed > 1 {
		fail(w, 409, "原应用请求记录不可核对；未重新提交")
		return
	}
	if closed == 1 {
		out, found, err := registryClosedOutcome(a.Store.DB, app, u.ID, key)
		if err != nil || !found {
			fail(w, 409, "原关闭记录身份不可核对；未重新提交")
			return
		}
		send(w, 200, out)
		return
	}
	if install+update == 0 {
		fail(w, 404, "尚未找到原应用请求记录；不能据此认定没有提交")
		return
	}
	var out registryRequestOutcome
	out.AppID, out.State = app, "unknown"
	if install == 1 {
		binding, found, err := a.Store.registryInstallBinding(app, u.ID, key)
		if err != nil || !found {
			fail(w, 409, "原应用安装身份或任务内容不可核对；未重新提交")
			return
		}
		out.Action, out.JobID, out.Provider, out.Version, out.SHA256 = "install", binding.JobID, binding.Provider, binding.Version, binding.SHA256
		if binding.Provider == "compose" {
			var job DockerJobResult
			if a.Executor != nil && a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/jobs/"+binding.JobID, nil, &job) == nil &&
				job.JobID == binding.JobID && job.ProjectID == binding.Scope && job.Kind == "compose" && validRegistryComposeJobState(job.State) {
				out.State, out.StateKnown = job.State, true
			}
			send(w, 200, out)
			return
		}
	} else {
		var actor, storedApp string
		err := a.Store.DB.QueryRow(`SELECT actor_id,app_id,version,sha256 FROM app_registry_update_requests WHERE idempotency_key=?`, key).Scan(&actor, &storedApp, &out.Version, &out.SHA256)
		if err != nil || actor != u.ID || storedApp != app {
			fail(w, 409, "原应用更新身份不可核对；未重新提交")
			return
		}
		binding, found, err := a.Store.registryUpdateReplay(app, u.ID, key, registryUpdateInput{out.Version, out.SHA256})
		if err != nil || !found {
			fail(w, 409, "原应用更新任务内容不可核对；未重新提交")
			return
		}
		out.Action, out.JobID, out.Provider = "update", binding.JobID, binding.Provider
	}
	var state string
	err := a.Store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, out.JobID).Scan(&state)
	if err != nil || !validRegistryComposeJobState(state) {
		if err != nil && !errors.Is(err, sql.ErrNoRows) { // Do not return raw SQL/job errors.
			fail(w, 503, "原应用任务状态暂时不可读取；未重新提交")
			return
		}
		fail(w, 409, "原应用任务状态不可核对；未重新提交")
		return
	}
	out.State, out.StateKnown = state, true
	send(w, 200, out)
}
