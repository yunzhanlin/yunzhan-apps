//go:build linux

package executor

import (
	"context"
	"net/http"
	"os"
	"time"

	"local/panel/internal/core"
)

// Exact original, side-effect-free status; it never invokes the legacy GET
// docker/jobs observer, creates run locks, reconciles Core receipts or restarts
// an interrupted worker. Compiled-key verification is still independent.
func (j *memcachedUnixJournal) status(ctx context.Context) (core.DockerJobResult, error) {
	var empty core.DockerJobResult
	head, err := j.read()
	if err != nil {
		return empty, err
	}
	authority, err := j.officialAuthority(ctx)
	if err != nil || !authority.Matches(head.Binding.Version, head.Binding.ManifestSHA256) || authority.CatalogSHA256() != head.CatalogSHA256 {
		return empty, errMemcachedUnixJournal
	}
	after, err := j.read()
	if err != nil || after != head || !j.current() || ctx == nil || ctx.Err() != nil {
		return empty, errMemcachedUnixJournal
	}
	return core.MemcachedUnixInstallResult(head)
}

func (s *Service) memcachedUnixInstallStatusRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/memcached-unix/installs/{job}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		job := r.PathValue("job")
		if !core.ValidID(job) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原 Socket 安装任务标识无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		j, err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).open(job)
		if os.IsNotExist(err) {
			respond(w, 404, map[string]string{"error": "尚未找到原任务；不能据此判断未提交，未重发"})
			return
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": "原 Socket 事务私有证据不能核对，未修复或重发"})
			return
		}
		defer j.Close()
		result, err := j.status(ctx)
		if err != nil || result.JobID != job {
			respond(w, 409, map[string]string{"error": "原 Socket 安装完整证据或官方验签未通过；不推断成功"})
			return
		}
		respond(w, 200, result)
	})
}
