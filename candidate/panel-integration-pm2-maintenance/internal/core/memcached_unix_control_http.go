package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func decodeMemcachedUnixControlInput(raw []byte) (MemcachedUnixControlInput, error) {
	var in MemcachedUnixControlInput
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixControlBytes {
		return in, ErrMemcachedUnixControl
	}
	fields, err := memcachedUnixWorkspaceObject(raw, map[string]bool{"action": true, "expected_runtime_sha256": true, "acknowledge_cache_loss": true, "acknowledge_removal": true, "confirm_name": true})
	if err != nil || json.Unmarshal(raw, &in) != nil {
		return in, ErrMemcachedUnixControl
	}
	if in.Action == "retire" {
		if len(fields) != 5 {
			return in, ErrMemcachedUnixControl
		}
	} else if len(fields) != 3 {
		return in, ErrMemcachedUnixControl
	}
	return in, nil
}
func (a *Server) memcachedUnixControlExecutor() *ExecutorClient {
	if a.Executor == nil || a.Executor.Client == nil {
		return nil
	}
	transport := *a.Executor.Client
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ExecutorClient{Client: &transport}
}
func (a *Server) memcachedUnixControlRoutes(m *http.ServeMux) {
	a.memcachedUnixControlReviewRoutes(m)
	m.HandleFunc("GET /api/app-registry/memcached/installs/{job}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		job := r.PathValue("job")
		if !ValidID(job) || r.URL.RawQuery != "" {
			fail(w, 404, "原安装任务无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if memcachedUpdateAuthority(ctx, a.Store.DB, actor.ID, "") != nil {
			fail(w, 403, "原安装查询需要当前完整管理员权限")
			return
		}
		var key string
		if a.Store.DB.QueryRowContext(ctx, "SELECT idempotency_key FROM app_registry_install_requests WHERE job_id=? AND actor_id=? AND app_id='memcached' AND version='1.6.45-compat4' AND provider='compose' AND target='memcached-cache'", job, actor.ID).Scan(&key) != nil {
			fail(w, 404, "该账户的原 Socket 安装任务不存在")
			return
		}
		r.SetPathValue("id", "memcached")
		r.SetPathValue("key", key)
		a.registryRequestStatus(w, r.WithContext(ctx), actor)
	}))
	m.HandleFunc("GET /api/app-registry/memcached/controls", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" {
			fail(w, 400, "启停记录查询不接受过滤身份")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		tx, err := a.Store.DB.BeginTx(ctx, nil)
		if err != nil {
			fail(w, 409, ErrMemcachedUnixControl.Error())
			return
		}
		defer tx.Rollback()
		if memcachedUpdateAuthority(ctx, tx, actor.ID, "") != nil || memcachedUnixControlSchema(ctx, tx) != nil {
			fail(w, 403, "启停记录需要当前完整管理员权限")
			return
		}
		rows, err := tx.QueryContext(ctx, "SELECT request_id FROM memcached_unix_controls WHERE actor_id=? OR state<>'completed' ORDER BY CASE state WHEN 'completed' THEN 1 ELSE 0 END,created_at DESC,request_id LIMIT 101", actor.ID)
		if err != nil {
			fail(w, 409, ErrMemcachedUnixControl.Error())
			return
		}
		var keys []string
		for rows.Next() {
			var key string
			if rows.Scan(&key) != nil {
				rows.Close()
				fail(w, 409, ErrMemcachedUnixControl.Error())
				return
			}
			keys = append(keys, key)
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			fail(w, 409, ErrMemcachedUnixControl.Error())
			return
		}
		truncated := len(keys) > 100
		if truncated {
			keys = keys[:100]
		}
		out := make([]memcachedUnixControlRow, 0, len(keys))
		for _, key := range keys {
			value, found, err := readMemcachedUnixControl(ctx, tx, key)
			if err != nil || !found || value.Operation.ActorID != actor.ID && value.State == "completed" {
				fail(w, 409, ErrMemcachedUnixControl.Error())
				return
			}
			out = append(out, value)
		}
		if tx.Commit() != nil {
			fail(w, 409, ErrMemcachedUnixControl.Error())
			return
		}
		send(w, 200, map[string]any{"records": out, "truncated": truncated})
	}))
	m.HandleFunc("POST /api/app-registry/memcached/instances/{project}/controls/{request}/close", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.PathValue("request")
		if !ValidID(project) || !ValidID(key) || r.URL.RawQuery != "" {
			fail(w, 404, "原启停请求无效")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16))
		if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
			fail(w, 400, "关闭操作不能携带新动作或身份")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 16*time.Second)
		defer cancel()
		row, found, err := a.Store.memcachedUnixControlForActor(ctx, actor.ID, key)
		if err != nil || !found || row.Operation.ProjectID != project {
			fail(w, 403, "当前账户不能关闭原请求")
			return
		}
		if row.Result != nil {
			send(w, 200, row)
			return
		}
		executor := a.memcachedUnixControlExecutor()
		if executor == nil {
			fail(w, 503, "没有关闭回执；保留原请求")
			return
		}
		var result MemcachedUnixControlResult
		if executor.Call(ctx, http.MethodPost, "/v1/memcached-unix/projects/"+project+"/controls/"+key+"/close", row.Operation, &result) != nil || ValidateMemcachedUnixControlResult(row.Operation, result) != nil || result.State == "unknown" {
			fail(w, 409, "不能确认尚未执行；保留原请求，不删除或重发")
			return
		}
		if a.Store.finishMemcachedUnixControlReply(ctx, actor.ID, row.Operation, &result) != nil {
			fail(w, 409, "关闭回执等待核对；不重发原生命令")
			return
		}
		row.State, row.Result = "completed", &result
		send(w, 200, row)
	}))
	m.HandleFunc("POST /api/app-registry/memcached/instances/{project}/controls", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.Header.Get("Idempotency-Key")
		if !ValidID(project) || r.URL.RawQuery != "" {
			fail(w, 404, "原实例身份无效")
			return
		}
		if !ValidID(key) || len(r.Header.Values("Idempotency-Key")) != 1 {
			fail(w, 400, "启停需要唯一的原请求编号")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMemcachedUnixControlBytes))
		in, decodeErr := decodeMemcachedUnixControlInput(raw)
		op := MemcachedUnixControlOperation{Format: 1, RequestID: key, ProjectID: project, ActorID: actor.ID, Input: in}
		if err != nil || decodeErr != nil || ValidateMemcachedUnixControlOperation(op) != nil {
			fail(w, 400, "原实时摘要、固定动作和缓存丢失确认不完整")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 48*time.Second)
		defer cancel()
		prior, found, err := a.Store.memcachedUnixControlForActor(ctx, actor.ID, key)
		if err != nil || found && prior.Operation != op {
			fail(w, 409, "原请求或当前完整管理员授权不能核对")
			return
		}
		if found {
			send(w, 200, prior)
			return
		} // SQL ONLY. Never dispatch/re-fetch/requeue.
		executor := a.memcachedUnixControlExecutor()
		if executor == nil {
			fail(w, 503, "启停服务不可用；未保留或提交")
			return
		}
		row, fresh, err := a.Store.reserveMemcachedUnixControl(ctx, op)
		if err != nil {
			fail(w, 409, ErrMemcachedUnixControl.Error())
			return
		}
		if !fresh {
			send(w, 200, row)
			return
		}
		var result MemcachedUnixControlResult
		callErr := executor.Call(ctx, http.MethodPost, "/v1/memcached-unix/projects/"+project+"/controls/"+key, op, &result)
		if callErr != nil || ValidateMemcachedUnixControlResult(op, result) != nil || result.State == "unknown" {
			persist, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer persistCancel()
			if a.Store.finishMemcachedUnixControl(persist, op, nil) != nil {
				fail(w, 409, "原回执暂不能结算；保留原编号，不重发")
				return
			}
			row.State = "unknown"
			send(w, 202, row)
			return
		}
		if a.Store.finishMemcachedUnixControlReply(ctx, actor.ID, op, &result) != nil {
			fail(w, 409, "真实启停回执已保留，Core 结算不能核对；只查询原编号")
			return
		}
		row.State, row.Result = "completed", &result
		send(w, 200, row)
	}))
	m.HandleFunc("GET /api/app-registry/memcached/instances/{project}/controls/{request}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.PathValue("request")
		if !ValidID(project) || !ValidID(key) || r.URL.RawQuery != "" {
			fail(w, 404, "原启停请求无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		row, found, err := a.Store.memcachedUnixControlForActor(ctx, actor.ID, key)
		if err != nil {
			fail(w, 403, "当前账户不能核对原启停请求")
			return
		}
		if !found || row.Operation.ProjectID != project {
			fail(w, 404, "原启停请求不存在")
			return
		}
		if row.Result != nil {
			send(w, 200, row)
			return
		}
		executor := a.memcachedUnixControlExecutor()
		if executor != nil {
			var result MemcachedUnixControlResult
			if executor.Call(ctx, http.MethodGet, "/v1/memcached-unix/projects/"+project+"/controls/"+key+"?actor_id="+actor.ID, nil, &result) == nil && ValidateMemcachedUnixControlResult(row.Operation, result) == nil && result.State != "unknown" {
				if a.Store.finishMemcachedUnixControlReply(ctx, actor.ID, row.Operation, &result) != nil {
					fail(w, 409, "原只读回执无法结算；不重发")
					return
				}
				row.State, row.Result = "completed", &result
			}
		}
		send(w, 200, row)
	}))
}

// SELECT only, no migration, resume, cancellation or invented original request.
func (s *Store) MemcachedUnixControlStatusBinding(ctx context.Context, actor, key string) (MemcachedUnixControlOperation, error) {
	row, found, err := s.memcachedUnixControlForActor(ctx, actor, key)
	if err != nil || !found {
		return MemcachedUnixControlOperation{}, ErrMemcachedUnixControl
	}
	return row.Operation, nil
}
