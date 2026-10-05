//go:build !linux

package executor

import "net/http"

func (s *Service) databaseConnectionRoutes(m *http.ServeMux) {}
