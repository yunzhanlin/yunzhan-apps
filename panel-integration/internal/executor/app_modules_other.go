//go:build !linux

package executor

import "net/http"

func (s *Service) appModuleRoutes(m *http.ServeMux) {}
func (s *Service) StartAppModuleWorker()            {}
