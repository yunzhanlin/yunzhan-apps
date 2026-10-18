//go:build !linux

package executor

import "net/http"

func runtimeReferenceRoutes(m *http.ServeMux) {}
