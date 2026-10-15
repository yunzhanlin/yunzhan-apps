package core

import (
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

// ValidSystemDirectory accepts only canonical absolute paths. The executor
// opens every component without following links and never reads file content.
func ValidSystemDirectory(value string) bool {
	if value == "/" {
		return true
	}
	if len(value) > 1024 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.Contains(value, "\\") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, ch := range part {
			if ch < 32 || ch == 127 {
				return false
			}
		}
	}
	return true
}

func (a *Server) systemFileRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/filesystem", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		directory := r.URL.Query().Get("path")
		if !ValidSystemDirectory(directory) || len(r.URL.Query().Get("search")) > 128 {
			fail(w, 400, "无效服务器目录或搜索条件")
			return
		}
		q := url.Values{"path": {directory}, "search": {r.URL.Query().Get("search")}, "page": {r.URL.Query().Get("page")}, "limit": {r.URL.Query().Get("limit")}}
		var out any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/filesystem?"+q.Encode(), nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
}
