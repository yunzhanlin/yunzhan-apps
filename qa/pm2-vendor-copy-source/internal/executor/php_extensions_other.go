//go:build !linux

package executor

import "net/http"

func phpExtensionRoutes(m *http.ServeMux) {}
