//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) sftpRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sftp/jobs", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 501, map[string]string{"error": "SFTP 账户管理仅支持 Linux"})
	})
}

func RunSFTPJob(string) error { return errors.New("SFTP 账户管理仅支持 Linux") }
