//go:build !linux

package executor

import "net/http"

type terminalManager struct{}

func newTerminalManager(string) *terminalManager { return &terminalManager{} }

func (s *Service) terminalRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/terminal/sessions", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 501, map[string]string{"error": "Web 终端仅支持 Linux"})
	})
}

func ServeTerminalSocket(string, string) error { return http.ErrNotSupported }
