//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) nodeRoutes(m *http.ServeMux) {}
func ServeNode(id string) error                { return errors.New("Node.js 项目仅支持 Linux") }
