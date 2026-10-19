//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) securityRoutes(m *http.ServeMux) {}
func FirewallRollback(string) error                { return errors.New("firewall is only available on Linux") }
func RecoverFirewall() error                       { return errors.New("firewall is only available on Linux") }
