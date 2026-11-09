//go:build !linux

package executor

import "net/http"

func (s *Service) fileRoutes(m *http.ServeMux) {}
