//go:build !linux

package executor

import "net/http"

func (s *Service) siteArchiveRoutes(m *http.ServeMux) {}
