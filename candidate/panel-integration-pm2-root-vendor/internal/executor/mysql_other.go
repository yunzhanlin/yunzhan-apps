//go:build !linux

package executor

import "net/http"

func mysqlRoutes(m *http.ServeMux) {}
