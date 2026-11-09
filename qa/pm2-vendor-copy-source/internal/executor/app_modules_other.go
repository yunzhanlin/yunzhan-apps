//go:build !linux

package executor

import (
	"context"
	"net/http"
)

func (s *Service) appModuleRoutes(m *http.ServeMux)            {}
func (s *Service) StartAppModuleWorker()                       {}
func (s *Service) StartAppModuleWorkerContext(context.Context) {}
