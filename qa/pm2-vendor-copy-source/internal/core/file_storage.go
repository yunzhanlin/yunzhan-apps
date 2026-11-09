package core

import (
	"context"
	"net/http"
	"time"
)

type FileStorageCategory struct {
	ID            string   `json:"id"`
	Label         string   `json:"label"`
	Paths         []string `json:"paths"`
	Bytes         *uint64  `json:"bytes"`
	State         string   `json:"state"`
	Scanned       int      `json:"scanned"`
	Skipped       int      `json:"skipped"`
	Deduplicated  int      `json:"deduplicated"`
	ForeignMounts int      `json:"foreign_mounts"`
	Reason        string   `json:"reason,omitempty"`
}

type FileStorageUsage struct {
	FilesystemPath string                `json:"filesystem_path"`
	DiskTotal      uint64                `json:"disk_total"`
	DiskUsed       uint64                `json:"disk_used"`
	DiskAvailable  uint64                `json:"disk_available"`
	OtherBytes     *uint64               `json:"other_bytes"`
	Categories     []FileStorageCategory `json:"categories"`
	Complete       bool                  `json:"complete"`
	Reconciled     bool                  `json:"reconciled"`
	Scanned        int                   `json:"scanned"`
	Limit          int                   `json:"limit"`
	StartedAt      string                `json:"started_at"`
	SampledAt      string                `json:"sampled_at"`
	DurationMS     int64                 `json:"duration_ms"`
}

func (a *Server) fileStorageRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/storage/usage", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if r.URL.RawQuery != "" {
			fail(w, 400, "存储统计不接受自定义目录")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var out FileStorageUsage
		if err := a.Executor.Call(ctx, "GET", "/v1/storage/usage", nil, &out); err != nil {
			fail(w, 503, "存储统计暂不可用")
			return
		}
		send(w, 200, out)
	}))
}
