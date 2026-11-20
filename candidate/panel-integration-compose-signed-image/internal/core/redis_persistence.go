package core

import "net/http"

type RedisPersistence struct {
	InstanceID           string `json:"instance_id"`
	LastSnapshot         int64  `json:"last_snapshot"`
	SnapshotDuration     int64  `json:"snapshot_duration_seconds"`
	ChangesSinceLastSave int64  `json:"changes_since_last_save"`
	SnapshotRunning      bool   `json:"snapshot_running"`
	SnapshotStatus       string `json:"snapshot_status"`
	AOFEnabled           bool   `json:"aof_enabled"`
	AOFRewriteRunning    bool   `json:"aof_rewrite_running"`
	AOFRewriteScheduled  bool   `json:"aof_rewrite_scheduled"`
	AOFWriteStatus       string `json:"aof_write_status"`
}

func (a *Server) redisPersistenceRoutes(m *http.ServeMux) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		m.HandleFunc(method+" /api/redis/instances/{id}/persistence", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			w.Header().Set("Cache-Control", "no-store")
			access, err := a.Store.UserAccess(u.ID)
			if err != nil || !redisCredentialsAccess(access) || len(access.SiteIDs) != 0 {
				fail(w, http.StatusForbidden, "Redis 持久化需要无站点限制的数据库管理员权限")
				return
			}
			id := r.PathValue("id")
			if !ValidID(id) {
				fail(w, http.StatusBadRequest, "Redis 实例标识无效")
				return
			}
			path := "/v1/redis/instances/" + id + "/persistence"
			if method == http.MethodGet {
				var out RedisPersistence
				if err := a.Executor.Call(r.Context(), method, path, nil, &out); err != nil {
					fail(w, http.StatusConflict, err.Error())
					return
				}
				if out.InstanceID != id {
					fail(w, http.StatusBadGateway, "Redis 持久化状态与实例不一致")
					return
				}
				send(w, http.StatusOK, out)
				return
			}
			var input struct {
				ConfirmID string `json:"confirm_id"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 512)
			if !decode(w, r, &input) {
				return
			}
			if input.ConfirmID != id {
				fail(w, http.StatusBadRequest, "Redis 快照确认与实例不一致")
				return
			}
			if err := a.Store.Audit(u.Username, "redis.snapshot.start", id, "requested"); err != nil {
				fail(w, http.StatusServiceUnavailable, "无法记录 Redis 快照请求")
				return
			}
			var out struct {
				InstanceID string `json:"instance_id"`
			}
			if err := a.Executor.Call(r.Context(), method, path, input, &out); err != nil {
				_ = a.Store.Audit(u.Username, "redis.snapshot.start", id, "unconfirmed")
				fail(w, http.StatusConflict, err.Error())
				return
			}
			if out.InstanceID != id {
				fail(w, http.StatusBadGateway, "Redis 快照结果待核对，请先刷新持久化状态")
				return
			}
			_ = a.Store.Audit(u.Username, "redis.snapshot.start", id, "accepted")
			send(w, http.StatusAccepted, out)
		}))
	}
}
