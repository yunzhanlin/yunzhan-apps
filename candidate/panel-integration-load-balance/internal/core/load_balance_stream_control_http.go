package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"local/panel/internal/loadbalancestream"
)

func (a *Server) loadBalanceStreamControlExecutor() *ExecutorClient {
	if a == nil || a.Executor == nil || a.Executor.Client == nil {
		return nil
	}
	client := *a.Executor.Client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ExecutorClient{Client: &client}
}

func (a *Server) loadBalanceStreamControlRoutes(m *http.ServeMux) {
	a.loadBalanceStreamWorkspaceRoutes(m)
	a.loadBalanceStreamControlHistoryRoutes(m)
	m.HandleFunc("POST /api/app-registry/load-balance/stream/controls/{request}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("request")
		if !ValidID(id) || r.URL.RawQuery != "" {
			fail(w, 400, "原始请求编号或查询参数无效")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, loadbalancestream.MaxEntryBytes))
		if err != nil {
			fail(w, 400, "TCP/UDP 请求超出固定容量")
			return
		}
		// This endpoint is the canonical versioned control wire. The browser
		// never sends an actor, grant, probe allocation, PID or renderer.
		mutation, err := loadbalancestream.DecodeMutation(raw)
		if err != nil {
			fail(w, 400, "TCP/UDP 变更格式或版本无效")
			return
		}
		op := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: id, ActorID: actor.ID, Mutation: mutation}
		executor := a.loadBalanceStreamControlExecutor()
		if executor == nil {
			fail(w, 503, "执行器不可用；没有建立或派发新请求")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		row, fresh, err := a.Store.reserveLoadBalanceStreamControl(ctx, op)
		if err != nil {
			fail(w, 409, errLoadBalanceStreamControl.Error())
			return
		}
		if fresh {
			// Independent of the browser connection; the durable CAS in the
			// worker, not this goroutine, decides the single dispatch.
			go func() {
				work, done := context.WithTimeout(context.Background(), time.Duration(loadbalancestream.RuntimeDrainSeconds+180)*time.Second)
				defer done()
				runLoadBalanceStreamControl(work, a.Store, executor, op, true)
				if work.Err() != nil {
					closeCtx, closeDone := context.WithTimeout(context.Background(), 3*time.Second)
					defer closeDone()
					_ = a.Store.markLoadBalanceStreamControlUnknown(closeCtx, op)
				}
			}()
		}
		send(w, 202, row)
	}))
	m.HandleFunc("GET /api/app-registry/load-balance/stream/controls/{request}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("request")
		if !ValidID(id) || r.URL.RawQuery != "" {
			fail(w, 404, "原始请求编号无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		row, found, err := a.Store.loadBalanceStreamControlForActor(ctx, actor.ID, id)
		if err != nil {
			fail(w, 403, "需要当前完整管理员及原请求身份")
			return
		}
		if !found {
			fail(w, 404, "原始请求不存在")
			return
		}
		// Pure DB history. Never POST, finish, create a native journal or infer
		// that a committed old transaction is today's runtime health.
		send(w, 200, row)
	}))
	m.HandleFunc("POST /api/app-registry/load-balance/stream/controls/{request}/close", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("request")
		if !ValidID(id) || r.URL.RawQuery != "" {
			fail(w, 400, "原始请求编号无效")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16))
		if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
			fail(w, 400, "关闭请求不能携带新动作或身份")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if _, err := a.Store.cancelUndispatchedLoadBalanceStreamControl(ctx, actor.ID, id); err != nil {
			fail(w, 409, "仅可关闭从未派发的原保留记录；已派发或不确定事务不会被伪装为已撤销")
			return
		}
		row, found, err := a.Store.loadBalanceStreamControlForActor(ctx, actor.ID, id)
		if err != nil || !found {
			fail(w, 409, errLoadBalanceStreamControl.Error())
			return
		}
		send(w, 200, row)
	}))
}
