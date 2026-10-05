//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) dockerRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 501, map[string]string{"error": "Docker 管理仅支持 Linux"})
	})
}

func RunDockerJob(string) error { return errors.New("Docker 管理仅支持 Linux") }
