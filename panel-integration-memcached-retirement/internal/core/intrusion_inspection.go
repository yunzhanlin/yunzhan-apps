package core

import (
	"io"
	"net/http"
	"net/url"
)

func (a *Server) intrusionInspectionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/intrusion-prevention/inspection", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		var out any
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/software/intrusion-prevention/inspection", nil, &out); err != nil {
			fail(w, 503, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/intrusion-prevention/workspace", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		var out any
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/software/intrusion-prevention/workspace", nil, &out); err != nil {
			fail(w, 503, "防入侵工作区状态尚未完整核对；未创建替代任务")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/intrusion-prevention/recover", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			fail(w, 400, "防入侵恢复请求过大或不完整")
			return
		}
		settings, err := decodeIntrusionActorBody(raw, u.ID, "recover")
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		job, err := a.Store.queueIntrusionRequest("recover", settings, r.Header.Get("Idempotency-Key"), u)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
	for _, action := range []string{"configure", "uninstall"} {
		m.HandleFunc("POST /api/software/intrusion-prevention/"+action, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			w.Header().Set("Cache-Control", "no-store")
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
			if err != nil {
				fail(w, 400, "防入侵请求必须是唯一完整的settings对象")
				return
			}
			settings, err := decodeIntrusionActorBody(raw, u.ID, action)
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			job, err := a.Store.queueIntrusionRequest(action, settings, r.Header.Get("Idempotency-Key"), u)
			if err != nil {
				fail(w, 409, err.Error())
				return
			}
			send(w, 202, map[string]string{"job_id": job})
		}))
	}
	m.HandleFunc("GET /api/software/intrusion-prevention/requests", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) > 1 || len(query["cursor"]) > 1 || len(query) == 1 && len(query["cursor"]) != 1 {
			fail(w, 400, "原请求目录游标无效")
			return
		}
		out, err := a.Store.readIntrusionRequests(u.ID, query.Get("cursor"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
}
