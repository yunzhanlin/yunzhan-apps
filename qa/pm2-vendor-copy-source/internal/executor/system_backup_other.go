//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) systemBackupRoutes(m *http.ServeMux) {}
func RestoreSystemBackup(string, string, string) error {
	return errors.New("system restore is only available on Linux")
}
