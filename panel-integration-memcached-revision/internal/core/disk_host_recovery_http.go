package core

import (
	"context"
	"net/http"
	"time"

	"local/panel/internal/diskjob"
)

// Explicit stop-and-close administration returns metadata only. Ordinary
// per-owner history/report access remains unchanged; no ownership adoption.
func (a *Server) diskHostRecoveryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/disk-analysis/host/recovery", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, err := a.Store.HostDiskInventoryRequest(r.Context(), u.ID); err != nil {
			fail(w, 403, "原任务维护仅完整管理员可读取")
			return
		}
		rows, err := a.Store.DB.QueryContext(r.Context(), "SELECT id,state,created_at,updated_at FROM disk_host_jobs WHERE state IN ('queued','dispatching','running','cancel_requested','uncertain') ORDER BY created_at,id LIMIT 129")
		if err != nil {
			fail(w, 503, "原任务维护清单无法读取")
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var id, state, created, updated string
			if rows.Scan(&id, &state, &created, &updated) != nil || !ValidID(id) || len(out) >= diskjob.ActiveJobsMax {
				fail(w, 409, "原任务维护清单无法核对")
				return
			}
			out = append(out, map[string]string{"id": id, "state": state, "created_at": created, "updated_at": updated})
		}
		if rows.Err() != nil {
			fail(w, 503, "原任务维护清单不完整")
			return
		}
		if _, err := a.Store.HostDiskInventoryRequest(r.Context(), u.ID); err != nil {
			fail(w, 403, "当前维护权限已改变")
			return
		}
		send(w, 200, map[string]any{"jobs": out, "metadata_only": true})
	}))
	m.HandleFunc("POST /api/software/disk-analysis/host/jobs/{id}/recover", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		j, request, err := a.Store.PrepareHostDiskRecovery(ctx, r.PathValue("id"), u.ID)
		if err != nil {
			fail(w, 403, "当前完整管理员授权或原任务记录不能核对")
			return
		}
		if request == nil {
			send(w, 200, map[string]any{"id": j.ID, "state": j.State, "terminal_verified": hostDiskTerminal(j.State), "metadata_only": true})
			return
		}
		var ack diskjob.RecoveryAck
		if err := a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/recover", request, &ack); err != nil || diskjob.ValidateRecoveryAck(ack, request.Request) != nil {
			fail(w, 409, "原任务停止或终结凭证暂不能核对；保留原ID等待核对，未重发")
			return
		}
		j, err = a.Store.FinishHostDiskRecovery(ctx, *request, ack)
		if err != nil {
			fail(w, 409, "原任务终结凭证或当前维护权限不能核对")
			return
		}
		send(w, 202, map[string]any{"id": j.ID, "state": j.State, "signal_requested": ack.SignalRequested, "terminal_verified": ack.Closure != nil, "metadata_only": true})
	}))
}
