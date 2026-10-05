//go:build !linux

package executor

import (
	"local/panel/internal/core"
	"net/http"
)

func (s *Service) phpWorkerRoutes(m *http.ServeMux)                    {}
func (s *Service) checkPHPWorkerSiteChange(in core.ApplyRequest) error { return nil }
