//go:build !linux

package executor

import "net/http"

func (s *Service) fail2banRoutes(m *http.ServeMux) {}
