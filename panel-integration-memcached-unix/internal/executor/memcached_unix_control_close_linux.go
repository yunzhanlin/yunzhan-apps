//go:build linux

package executor

import (
	"context"
	"io"
	"net/http"
	"time"

	"local/panel/internal/core"
)

// Explicitly close only an original request with NO issued daemon intent.
// This never resumes/rolls back a native action or deletes uncertain evidence.
// A late original POST sees its retained refused record (or closed Core row).
func closeMemcachedUnixControl(ctx context.Context, op core.MemcachedUnixControlOperation) (core.MemcachedUnixControlResult, error) {
	var empty core.MemcachedUnixControlResult
	if ctx == nil || ctx.Err() != nil || core.ValidateMemcachedUnixControlOperation(op) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return empty, err
	}
	defer reader.Close()
	p, err := openMemcachedUnixProjectOriginal(ctx, op.ProjectID)
	if err != nil {
		return empty, err
	}
	defer p.Close()
	check := func() error {
		original, err := (&core.Store{DB: reader.db}).MemcachedUnixControlStatusBinding(ctx, op.ActorID, op.RequestID)
		if err != nil || original != op || !reader.current() || p.current(ctx) != nil || reader.unixOperation(ctx, op.ActorID, p.head.Operation, "stop", p.head.Binding) != nil {
			return core.ErrMemcachedUnixControl
		}
		return nil
	}
	if check() != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(bound)
	cancel()
	if err != nil {
		return empty, err
	}
	defer lifetime.Close()
	if !lifetime.current() || check() != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	seed := memcachedUnixControlSeed{Format: 1, Operation: op, InstalledRecordSHA256: memcachedUnixControlInstalledSHA(p.head)}
	j, _, err := (memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}).prepare(seed)
	if err != nil {
		return empty, err
	}
	defer j.Close()
	lease, err := j.lease()
	if err != nil {
		return empty, err
	}
	defer lease.Close()
	value, err := j.read()
	if err != nil || !memcachedUnixControlMatchesOriginal(value, p) || value.Seed.Operation != op || check() != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	if value.Result != nil {
		if value.Result.State == "unknown" {
			return empty, core.ErrMemcachedUnixControl
		}
		return *value.Result, nil
	}
	if value.Issued != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	result := memcachedUnixControlBaseResult(op, "refused")
	if !lifetime.current() || check() != nil || lease.finish(result) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	return result, nil
}
func (s *Service) memcachedUnixControlClosureRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/memcached-unix/projects/{id}/controls/{request}/close", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(r.PathValue("id")) || !core.ValidID(r.PathValue("request")) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原启停请求身份无效"})
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUnixControlBytes+1))
		op, decodeErr := core.DecodeMemcachedUnixControlOperation(raw)
		if err != nil || decodeErr != nil || op.ProjectID != r.PathValue("id") || op.RequestID != r.PathValue("request") {
			respond(w, 400, map[string]string{"error": "关闭操作须绑定原请求，不能选择新动作"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		value, err := closeMemcachedUnixControl(ctx, op)
		if err != nil {
			respond(w, 409, map[string]string{"error": "不能证明原请求尚未发出原生命令；保留原记录，不关闭、删除或重发"})
			return
		}
		respond(w, 200, value)
	})
}
