//go:build !linux

package executor

import "net/http"

func (s *Service) lifecycleRoutes(m *http.ServeMux) {}
func (s *Service) lockRuntimeUse() (func(), error)  { return func() {}, nil }
func retiredInventory() ([]map[string]any, error)   { return []map[string]any{}, nil }
