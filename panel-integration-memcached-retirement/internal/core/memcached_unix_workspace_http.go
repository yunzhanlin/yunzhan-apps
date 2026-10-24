package core

import (
	"context"
	"io"
	"net/http"
	"time"

	"local/panel/internal/appcatalog"
)

// Values remain in this request/response only. No task payload, audit body,
// idempotency storage, file, command argv or automatic POST retry is created.
func (a *Server) memcachedUnixWorkspaceRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/app-registry/memcached/instances/{project}/workspace", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project := r.PathValue("project")
		if !ValidID(project) || r.URL.RawQuery != "" {
			fail(w, 404, "原缓存项目身份无效")
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMemcachedUnixWorkspaceBytes))
		defer clear(raw)
		input, decodeErr := decodeMemcachedUnixWorkspaceInput(raw)
		if readErr != nil || decodeErr != nil {
			fail(w, 400, "缓存操作输入或容量无效")
			return
		}
		transfer := MemcachedUnixWorkspaceRequest{Format: 1, ProjectID: project, ActorID: actor.ID, Action: input.Action, Cache: input.Cache}
		if ValidateMemcachedUnixWorkspaceRequest(transfer) != nil {
			fail(w, 400, "缓存操作、版本标记或编码不符合固定策略")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 16*time.Second)
		defer cancel()
		access, err := readUserAccessContext(ctx, a.Store.DB, actor.ID)
		if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
			fail(w, 403, "缓存工作区需要当前完整主机管理员权限")
			return
		}
		if a.Executor == nil || a.Executor.Client == nil {
			fail(w, 503, "缓存执行服务不可用；未提交或重试")
			return
		}
		transport := *a.Executor.Client
		transport.Jar = nil
		transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		executor := &ExecutorClient{Client: &transport}
		var out MemcachedUnixWorkspace
		if err := executor.Call(ctx, http.MethodPost, "/v1/memcached-unix/projects/"+project+"/workspace", transfer, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		path, pathErr := MemcachedUnixDirectory(project, out.SiteID)
		validState := out.State == "running" || out.State == "stopped" || out.State == "retired"
		validRetirement := out.State == "retired" && ValidID(out.RetirementRequestID) && !out.RetirementSupported || out.State != "retired" && out.RetirementRequestID == ""
		if out.Format != 1 || out.ProjectID != project || out.Version != appcatalog.MemcachedUnixVersion || !registryDigestValid(out.RuntimeSHA256) || !out.StateKnown || !validState || !validRetirement || out.Healthy != (out.State == "running") || pathErr != nil || out.SocketPath != path+"/cache.sock" || out.CacheMB != 128 || out.MemoryLimitMB != 192 || out.ItemLimitMB != 4 || out.EditorLimitBytes != MemcachedUnixConsoleValueBytes || out.NetworkMode != "none" || input.Action == "cache" && (out.State != "running" || out.Cache == nil || out.Cache.Action != input.Cache.Action) || input.Action == "inspect" && out.Cache != nil {
			fail(w, 409, "原缓存工作区结果不能核对；不推断成功，不重发写操作")
			return
		}
		send(w, 200, out)
	}))
}
