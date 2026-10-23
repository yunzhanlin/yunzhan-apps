//go:build !linux

package executor

import "net/http"

func (s *Service) monitorProcessRoutes(m *http.ServeMux) {}
