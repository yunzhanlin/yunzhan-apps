//go:build !linux

package executor

import (
	"local/panel/internal/core"
	"net/http"
)

func (s *Service) softwareRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, []core.SoftwareAppStatus{}) })
	m.HandleFunc("GET /v1/software/nginx-waf/events", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 409, map[string]string{"error": "安全软件只支持 Linux"})
	})
	m.HandleFunc("POST /v1/software/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 409, map[string]string{"error": "安全软件只支持 Linux"})
	})
}
