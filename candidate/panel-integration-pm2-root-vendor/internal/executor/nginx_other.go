//go:build !linux

package executor

import "net/http"

func (s *Service) nginxBinary() (string, error) { return s.Config.NginxBin, nil }
func (s *Service) nginxRoutes(m *http.ServeMux) {}
func activeNginx() (string, error)              { return "nginx-system", nil }
