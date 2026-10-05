//go:build !linux

package executor

import "net/http"

func (s *Service) siteTrafficRoutes(m *http.ServeMux) {}
