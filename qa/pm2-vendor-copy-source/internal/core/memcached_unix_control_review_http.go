package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func decodeMemcachedUnixControlReviewInput(raw []byte) (MemcachedUnixControlReviewInput, error) {
	var in MemcachedUnixControlReviewInput
	if len(raw) == 0 || len(raw) > 1024 {
		return in, ErrMemcachedUnixControl
	}
	fields, err := memcachedUnixWorkspaceObject(raw, map[string]bool{"expected_runtime_sha256": true, "acknowledge_original_unknown": true})
	if err != nil || len(fields) != 2 || json.Unmarshal(raw, &in) != nil || !registryDigestValid(in.ExpectedRuntimeSHA256) || !in.AcknowledgeOriginalUnknown {
		return in, ErrMemcachedUnixControl
	}
	return in, nil
}
func (a *Server) memcachedUnixControlReviewRoutes(m *http.ServeMux) {
	handle := func(w http.ResponseWriter, r *http.Request, actor identity) {
		w.Header().Set("Cache-Control", "no-store")
		project, key := r.PathValue("project"), r.PathValue("request")
		if !ValidID(project) || !ValidID(key) || r.URL.RawQuery != "" {
			fail(w, 404, "原启停复核身份无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 24*time.Second)
		defer cancel()
		op, err := a.Store.MemcachedUnixControlReviewBinding(ctx, actor.ID, key)
		if err != nil || op.ProjectID != project {
			fail(w, 403, "复核需要当前完整主机管理员权限与原始保留请求")
			return
		}
		in := MemcachedUnixControlReviewRequest{Format: 1, Operation: op, ReviewerID: actor.ID}
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			input, decodeErr := decodeMemcachedUnixControlReviewInput(raw)
			if err != nil || decodeErr != nil {
				fail(w, 400, "须明确确认原结果仍未知并提交刚核对的状态摘要，不能携带启停命令或身份")
				return
			}
			in.Input = &input
		}
		executor := a.memcachedUnixControlExecutor()
		if executor == nil {
			fail(w, 503, "复核服务不可用；保留原请求，不重新执行命令")
			return
		}
		var out MemcachedUnixControlReviewView
		if executor.Call(ctx, http.MethodPost, "/v1/memcached-unix/projects/"+project+"/controls/"+key+"/review", in, &out) != nil || ValidateMemcachedUnixControlReviewView(op, out) != nil {
			fail(w, 409, "原请求或真实当前状态不能核对；保留原记录，不重发原生命令")
			return
		}
		// GET is a preview only, including when Root already has a historical
		// observation. Only an explicit POST synchronizes that separate receipt.
		if r.Method == http.MethodPost {
			if out.Observation == nil {
				fail(w, 409, "没有独立复核回执；未结算、清除或重发原请求")
				return
			}
			if a.Store.finishMemcachedUnixControlReview(ctx, actor.ID, op, *out.Observation) != nil {
				fail(w, 409, "原生复核记录已保留，Core 等待核对；只读原编号，不重复执行")
				return
			}
		} else {
			// A revoke during the read must not leak the retained cross-actor view.
			current, e := a.Store.MemcachedUnixControlReviewBinding(ctx, actor.ID, key)
			if e != nil || current != op {
				fail(w, 403, "当前复核权限已变化")
				return
			}
		}
		send(w, 200, out)
	}
	m.HandleFunc("GET /api/app-registry/memcached/instances/{project}/controls/{request}/review", a.authorize(handle))
	m.HandleFunc("POST /api/app-registry/memcached/instances/{project}/controls/{request}/review", a.authorize(handle))
}
