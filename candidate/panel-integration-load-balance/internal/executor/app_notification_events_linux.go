//go:build linux

package executor

import (
	"net/http"
	"strconv"
)

func (s *Service) moduleAlertRoutes(m *http.ServeMux) {
	s.loadBalanceAlertRoutes(m)
	m.HandleFunc("GET /v1/module-alert-events", func(w http.ResponseWriter, r *http.Request) {
		module := r.URL.Query().Get("module")
		allowed := false
		for _, id := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "files-sync", "php-code-security"} {
			allowed = allowed || module == id
		}
		cursor, e := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
		if !allowed || e != nil || cursor < -1 {
			respond(w, 400, map[string]string{"error": "事件游标或模块无效"})
			return
		}
		if r.Context().Err() != nil {
			return
		}
		page, err := s.moduleAlertPage(r.Context(), module, cursor)
		if r.Context().Err() != nil {
			return
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": "应用告警源无法完整只读核对；原历史和游标保留"})
			return
		}
		respond(w, 200, page)
	})
}
