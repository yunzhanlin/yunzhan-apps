//go:build linux

package executor

import (
	"context"
	"net/http"
	"os"
	"time"

	"local/panel/internal/core"
)

func (j *memcachedUpdateJournal) snapshot(ctx context.Context) (core.MemcachedUpdateSnapshot, error) {
	var empty core.MemcachedUpdateSnapshot
	authority, err := j.officialAuthority(ctx)
	if err != nil {
		return empty, err
	}
	chain, err := j.readChain()
	if err != nil {
		return empty, err
	}
	first := chain[0]
	if !authority.Matches(first.Dispatch.Input.ExpectedVersion, first.Dispatch.Input.ExpectedSHA256) || authority.CatalogSHA256() != first.CatalogSHA256 || !j.d.current() || ctx.Err() != nil {
		return empty, core.ErrMemcachedUpdateSnapshotIdentity
	}
	return core.MemcachedUpdateSnapshot{Format: 1, Records: chain}, nil
}

func (s *Service) memcachedAppUpdateStatusRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/projects/{id}/app-updates/{job}", func(w http.ResponseWriter, r *http.Request) {
		project, job := r.PathValue("id"), r.PathValue("job")
		if !core.ValidID(project) || !core.ValidID(job) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原更新项目或任务标识无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		j, err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).open(job)
		if os.IsNotExist(err) {
			respond(w, 404, map[string]string{"error": "尚未找到原事务；不能据此认定没有提交"})
			return
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": "原更新事务私有记录不能核对，未修复或重发"})
			return
		}
		defer j.Close()
		head, err := j.read()
		if err != nil || head.Dispatch.ProjectID != project {
			respond(w, 409, map[string]string{"error": "原更新任务与项目身份不能核对"})
			return
		}
		snapshot, err := j.snapshot(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原事务完整证据或官方独立验签未通过；未执行或重发"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, 200, snapshot)
	})
}
