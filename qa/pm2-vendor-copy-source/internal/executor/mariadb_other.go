//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) mariadbRoutes(m *http.ServeMux) {}
func ServeMariaDB(id string) error                { return errors.New("MariaDB instances require Linux") }
func InitMariaDB(id string) error                 { return errors.New("MariaDB instances require Linux") }
