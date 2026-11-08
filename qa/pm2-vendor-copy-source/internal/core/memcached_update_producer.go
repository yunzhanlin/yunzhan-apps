package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"local/panel/internal/appcatalog"
)

func memcachedOriginalUpdateStatus(row memcachedUpdateReservation) memcachedUpdateStatus {
	out := memcachedUpdateStatus{AppID: "memcached", ProjectID: row.Seed.Dispatch.ProjectID, RequestID: row.Seed.Dispatch.RequestID, JobID: row.Seed.Dispatch.JobID, State: row.State, ExpectedVersion: row.Seed.Dispatch.Input.ExpectedVersion, ExpectedSHA256: row.Seed.Dispatch.Input.ExpectedSHA256, Detail: "已保留原更新请求；只核对该原任务，不重新提交"}
	if len(row.Chain) > 0 {
		out.StateKnown = true
		out.LastRecordSHA = row.Chain[len(row.Chain)-1].RecordSHA256
	}
	return out
}

// One authenticated, explicitly cache-loss-acknowledged original submission.
// A repeat key reads SQL only, even while offline/unknown; never re-fetches a
// catalog, changes an actor/job or repeats a native POST.
func (a *Server) memcachedUpdateProducerRoutes(m *http.ServeMux) {
	a.memcachedUpdateCloseRoutes(m)
	m.HandleFunc("POST /api/app-registry/{id}/instances/{project}/updates", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.Header.Get("Idempotency-Key")
		if r.PathValue("id") != "memcached" || !ValidID(project) || r.URL.RawQuery != "" {
			fail(w, 404, "不支持的原应用或项目")
			return
		}
		if !ValidID(key) || len(r.Header.Values("Idempotency-Key")) != 1 {
			fail(w, 400, "必须指定唯一的原更新请求标识")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxMemcachedUpdateInputBytes+1))
		input, decodeErr := DecodeMemcachedUpdateInput(raw)
		if err != nil || decodeErr != nil {
			fail(w, 400, "版本、摘要、原项目和缓存清空确认必须完整且无重复字段")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		prior, found, err := a.Store.memcachedUpdateForActor(ctx, actor.ID, key)
		if err != nil {
			fail(w, 403, "当前账户不能核对原更新请求")
			return
		}
		if found {
			if prior.Seed.Dispatch.ProjectID != project || prior.Seed.Dispatch.Input != input {
				fail(w, 409, "原请求标识已绑定不同更新；未覆盖或重发")
				return
			}
			send(w, 202, memcachedOriginalUpdateStatus(prior))
			return
		}
		closed, wasClosed, err := a.Store.memcachedClosureForActor(ctx, actor.ID, project, key)
		if err != nil {
			fail(w, 409, "原请求关闭记录不能核对，未提交更新")
			return
		}
		if wasClosed {
			if closed.Input != input {
				fail(w, 409, "原关闭编号已绑定不同输入，未覆盖或重发")
				return
			}
			send(w, 200, closureStatus(closed))
			return
		}
		if a.Executor == nil || a.Executor.Client == nil || a.AppCatalog == nil {
			fail(w, 503, "更新服务暂不可用，尚未保留更新请求")
			return
		}
		access, err := readUserAccessContext(ctx, a.Store.DB, actor.ID)
		if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 {
			fail(w, 403, "主机容器更新需要当前完整管理员权限")
			return
		}
		envelope, err := a.AppCatalog.FetchMemcachedReleaseEnvelope(ctx, input.ExpectedVersion, input.ExpectedSHA256)
		if err != nil {
			fail(w, 409, "官方应用目录已变化或交付不能验证；尚未提交更新")
			return
		}
		if _, err = appcatalog.VerifyMemcachedReleaseEnvelope(ctx, envelope, input.ExpectedVersion, input.ExpectedSHA256); err != nil {
			fail(w, 409, "官方固定处理器交付未通过独立验证")
			return
		}
		transport := *a.Executor.Client
		transport.Jar = nil
		transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		executor := &ExecutorClient{Client: &transport}
		var planRaw json.RawMessage
		if executor.Call(ctx, http.MethodGet, "/v1/docker/projects/"+project+"/app-update-plan", nil, &planRaw) != nil {
			fail(w, 409, "原项目预检暂不能核对；尚未提交更新")
			return
		}
		var plan MemcachedUpdatePlan
		if json.Unmarshal(planRaw, &plan) != nil || ValidateMemcachedUpdatePlan(plan, project) != nil {
			fail(w, 409, "原项目预检回复不能验证")
			return
		}
		canonical, _ := json.Marshal(plan)
		if !bytes.Equal(bytes.TrimSpace(planRaw), canonical) || plan.ProjectSHA256 != input.ExpectedProjectSHA256 {
			fail(w, 409, "原项目配置或预检身份已变化，请重新核对；尚未提交更新")
			return
		}
		if plan.AlreadyPinned {
			fail(w, 409, "原实例已使用目标固定镜像，无需更新；未保留请求或重建容器")
			return
		}
		dispatch := MemcachedUpdateDispatch{Format: 1, JobID: ID(), RequestID: key, ActorID: actor.ID, AccessRevision: strconv.FormatInt(access.Revision, 10), ProjectID: project, Input: input}
		seed, err := NewMemcachedUpdateSeed(dispatch, plan, envelope)
		if err != nil {
			fail(w, 409, "原更新交付绑定不能验证")
			return
		}
		row, fresh, err := a.Store.reserveMemcachedUpdate(ctx, actor.ID, seed)
		if err != nil {
			fail(w, 409, "原项目已有保留更新或当前授权已变化；未重复提交")
			return
		}
		if !fresh {
			send(w, 202, memcachedOriginalUpdateStatus(row))
			return
		}
		// Persist uncertainty BEFORE the one outbound POST. Even a crash before
		// transmission is not permission for a later request to resend it.
		persist, stop := context.WithTimeout(context.Background(), 3*time.Second)
		err = a.Store.markMemcachedUpdateUnknown(persist, actor.ID, key)
		stop()
		if err != nil {
			send(w, 202, memcachedOriginalUpdateStatus(row))
			return
		}
		row.State = "unknown"
		var snapshotRaw json.RawMessage
		if executor.Call(ctx, http.MethodPost, "/v1/docker/projects/"+project+"/app-updates/"+dispatch.JobID, MemcachedUpdateSubmission{Record: seed, Envelope: envelope}, &snapshotRaw) == nil {
			if snapshot, err := DecodeMemcachedUpdateSnapshot(snapshotRaw); err == nil {
				persist, stop := context.WithTimeout(context.Background(), 3*time.Second)
				updated, err := a.Store.reconcileMemcachedUpdate(persist, key, snapshot.Records)
				stop()
				if err == nil {
					row = updated
				}
			}
		}
		send(w, 202, memcachedOriginalUpdateStatus(row))
	}))
}

// Read-only native observation plus one explicit Core SQL reconciliation. This
// never sends a POST, queues a job, restarts a worker or clears a missing job.
func observeMemcachedUpdates(ctx context.Context, s *Store, e *ExecutorClient) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || e == nil || e.Client == nil {
		return
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	rows, err := memcachedUpdateInventory(ctx, tx)
	endErr := tx.Rollback()
	if err != nil || endErr != nil {
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		if row.State == "committed" || row.State == "rolled_back" || row.State == "failed_safe" || row.State == "needs_attention" {
			continue
		}
		bound, cancel := context.WithTimeout(ctx, 4*time.Second)
		snapshot, err := e.readMemcachedUpdateSnapshot(bound, row.Seed.Dispatch.ProjectID, row.Seed.Dispatch.JobID)
		if err == nil {
			_, _ = s.reconcileMemcachedUpdate(bound, row.Seed.Dispatch.RequestID, snapshot.Records)
		}
		cancel()
	}
}

func RunMemcachedUpdateObserver(ctx context.Context, s *Store, e *ExecutorClient) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bound, cancel := context.WithTimeout(ctx, 10*time.Second)
			observeMemcachedUpdates(bound, s, e)
			cancel()
		}
	}
}
