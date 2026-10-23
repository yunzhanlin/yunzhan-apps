//go:build !linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"net/http"
)

const certificateRoot = "/etc/panel/certificates"

func LoadCertificate(id string) (core.Certificate, error) {
	return core.Certificate{}, errors.New("证书部署需要 Linux 执行器")
}
func (s *Service) certificateRoutes(m *http.ServeMux) {}
