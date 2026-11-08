//go:build !linux

package executor

import "net/http"

func (s *Service) platformMaintenanceRoutes(m *http.ServeMux) {
	m.HandleFunc("/v1/platform-maintenance/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 501, map[string]string{"error": "原生维护只支持已核对的 Linux"})
	})
}
