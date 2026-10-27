package core

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Runtime configuration evidence only, not forwarded business/backend health.
const LoadBalanceStreamWorkspaceMaxBytes = loadbalancestream.MaxEntries*loadbalancestream.MaxEntryBytes + 16384

type LoadBalanceStreamWorkspace struct {
	Format                int                       `json:"format"`
	Version               string                    `json:"version"`
	Available             bool                      `json:"available"`
	State                 string                    `json:"state"`
	Detail                string                    `json:"detail"`
	BindAddress           string                    `json:"bind_address"`
	ConfigurationVerified bool                      `json:"configuration_verified"`
	Generation            int64                     `json:"generation"`
	RequestID             string                    `json:"request_id"`
	ConfigurationSHA256   string                    `json:"configuration_sha256"`
	Entries               []loadbalancestream.Entry `json:"entries"`
	AvailableMemoryBytes  int64                     `json:"available_memory_bytes"`
	MemoryHighBytes       int64                     `json:"memory_high_bytes"`
	MemoryMaxBytes        int64                     `json:"memory_max_bytes"`
	RetiringWorkers       int                       `json:"retiring_workers"`
}

func ValidateLoadBalanceStreamWorkspace(v LoadBalanceStreamWorkspace) error {
	bad := errLoadBalanceStreamControl
	if v.Format != 1 || v.Version != loadbalancestream.AppVersion || v.BindAddress != "127.0.0.1" ||
		len(v.Detail) == 0 || len(v.Detail) > 2048 || v.Entries == nil || len(v.Entries) > loadbalancestream.MaxEntries ||
		v.Generation < 0 || v.Generation > 128 || v.AvailableMemoryBytes < 0 || v.AvailableMemoryBytes > 1<<60 ||
		v.RetiringWorkers < 0 || v.RetiringWorkers > 1 {
		return bad
	}
	if !v.Available && v.State != "unavailable" {
		return bad
	}
	switch v.State {
	case "unavailable", "empty", "busy-or-unknown", "unknown", "degraded":
		if v.ConfigurationVerified {
			return bad
		}
	case "running", "stopped":
		if !v.Available || !v.ConfigurationVerified || v.Generation == 0 {
			return bad
		}
	default:
		return bad
	}
	if v.State != "unavailable" && !v.Available {
		return bad
	}
	if (v.State == "unavailable" || v.State == "empty" || v.State == "busy-or-unknown") && v.Generation != 0 || v.State == "degraded" && v.Generation == 0 || v.State != "running" && v.RetiringWorkers != 0 {
		return bad
	}
	if v.Generation == 0 {
		if len(v.Entries) != 0 || v.RequestID != "" || v.ConfigurationSHA256 != "" || v.MemoryHighBytes != 0 || v.MemoryMaxBytes != 0 || v.RetiringWorkers != 0 {
			return bad
		}
		return nil
	}
	if !ValidID(v.RequestID) || !streamControlDigest(v.ConfigurationSHA256) || v.MemoryHighBytes < loadbalancestream.ServiceBaseMemory ||
		v.MemoryMaxBytes < v.MemoryHighBytes || v.MemoryMaxBytes > loadbalancestream.ServiceBaseMemory+loadbalancestream.MaxMemoryBudget+loadbalancestream.MaxMemoryBudget/4 {
		return bad
	}
	runtime, err := loadbalancestream.RenderRuntime(v.Entries, loadbalancestream.ServiceRuntimePrefix,
		loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil || runtime.SHA256 != v.ConfigurationSHA256 || v.State == "running" && runtime.ActiveEntries == 0 ||
		v.State == "stopped" && (runtime.ActiveEntries != 0 || v.RetiringWorkers != 0) {
		return bad
	}
	return nil
}

func (a *Server) loadBalanceStreamWorkspaceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-registry/load-balance/stream/workspace", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" {
			fail(w, 400, "原生状态查询不接受身份或路径参数")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		access, err := readUserAccessContext(ctx, a.Store.DB, actor.ID)
		if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
			fail(w, 403, "需要当前完整主机管理员权限")
			return
		}
		executor := a.loadBalanceStreamControlExecutor()
		if executor == nil {
			fail(w, 503, "执行器不可用；未把旧缓存作为当前状态")
			return
		}
		var raw json.RawMessage
		if err := executor.Call(ctx, http.MethodGet, "/v1/load-balance-stream/workspace", nil, &raw); err != nil {
			fail(w, 409, "实际原生状态无法核对；未执行变更")
			return
		}
		var out LoadBalanceStreamWorkspace
		if json.Unmarshal(raw, &out) != nil || ValidateLoadBalanceStreamWorkspace(out) != nil {
			fail(w, 409, "原生状态的身份、完整配置或资源信息无法核对")
			return
		}
		send(w, 200, out)
	}))
}
