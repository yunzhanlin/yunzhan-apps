//go:build !linux

package executor

import "net/http"

func (s *Service) siteSecurityScanRoutes(m *http.ServeMux) {}
