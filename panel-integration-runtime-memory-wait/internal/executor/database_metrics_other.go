//go:build !linux

package executor

import "net/http"

func (s *Service) databaseMetricRoutes(m *http.ServeMux) {}
