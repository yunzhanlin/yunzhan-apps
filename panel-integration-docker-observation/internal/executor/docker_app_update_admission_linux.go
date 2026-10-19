//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

// Registered on the outer Docker mux, not a bypass in the generic mutation
// middleware. This exact route has its OWN independent compiled-key/Core/live
// admission; only its original worker may acquire the raw engine capability.
// Core's prior atomic reservation also fences concurrent program upgrade.
func (s *Service) memcachedAppUpdateAdmissionRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/docker/projects/{id}/app-updates/{job}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		project, job := r.PathValue("id"), r.PathValue("job")
		if !core.ValidID(project) || !core.ValidID(job) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原更新项目或任务无效"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUpdateSubmissionBytes+1))
		in, decodeErr := core.DecodeMemcachedUpdateSubmission(body)
		if err != nil || decodeErr != nil || in.Record.Dispatch.ProjectID != project || in.Record.Dispatch.JobID != job {
			respond(w, 400, map[string]string{"error": "原交付结构、容量或身份绑定无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		a, err := appcatalog.VerifyMemcachedReleaseEnvelope(ctx, in.Envelope, in.Record.Dispatch.Input.ExpectedVersion, in.Record.Dispatch.Input.ExpectedSHA256)
		if err != nil || !a.Matches(in.Record.Dispatch.Input.ExpectedVersion, in.Record.Dispatch.Input.ExpectedSHA256) || a.CatalogSHA256() != in.Record.CatalogSHA256 {
			respond(w, 409, map[string]string{"error": "执行器独立官方验签未通过，未保留任务或变更容器"})
			return
		}
		store := memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}
		original, openErr := store.open(job)
		if openErr == nil {
			defer original.Close()
			chain, err := original.readChain()
			if err != nil || len(chain) == 0 || chain[0] != in.Record {
				respond(w, 409, map[string]string{"error": "原任务已有不同或不完整证据，未覆盖或重发"})
				return
			}
			snapshot, err := original.snapshot(ctx)
			if err != nil {
				respond(w, 409, map[string]string{"error": "原任务暂不能核对，未重新排队"})
				return
			}
			respond(w, 200, snapshot)
			return
		}
		if !os.IsNotExist(openErr) || upgradeguard.Blocked() {
			respond(w, 409, map[string]string{"error": "原事务位置或程序升级状态不能核对"})
			return
		}
		reader, err := openMemcachedUpdateCoreAuthority(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": "受信原账户和保留请求不能核对"})
			return
		}
		defer reader.Close()
		if reader.check(ctx, in.Record) != nil {
			respond(w, 403, map[string]string{"error": "原更新保留请求或当前完整管理员授权无效"})
			return
		}
		plan, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, project, memcachedUpdateDockerRead)
		if err != nil || plan != in.Record.Plan {
			respond(w, 409, map[string]string{"error": "原 Memcached 服务已变化，未创建更新任务"})
			return
		}
		d, err := openComposeUpdateDirectory(dockerProjects, project)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原项目受信位置变化"})
			return
		}
		defer d.Close()
		compose, _, ce := d.read("compose.yaml", 48<<10)
		metadata, _, me := d.read("metadata.json", 16<<10)
		envelope, _ := json.Marshal(in.Envelope)
		seed := memcachedUpdateJournalSeed{Record: in.Record, Envelope: envelope, OriginalCompose: compose, OriginalMetadata: metadata}
		if ce != nil || me != nil || memcachedUpdateSeedValid(seed) != nil || reader.check(ctx, in.Record) != nil || upgradeguard.Blocked() || ctx.Err() != nil {
			respond(w, 409, map[string]string{"error": "原项目或授权在保留前变化，未变更容器"})
			return
		}
		_, fresh, err := store.prepare(seed)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原事务持久化结果不能核对，保留原证据，不重发"})
			return
		}
		if fresh {
			go runMemcachedAppUpdate(job)
		}
		j, err := store.open(job)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原任务已保留但暂不能读取，不重发"})
			return
		}
		defer j.Close()
		snapshot, err := j.snapshot(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原任务已保留，状态暂不能确认，不重发"})
			return
		}
		respond(w, 202, snapshot)
	})
}
