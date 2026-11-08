//go:build !linux

package executor

import (
	"context"
	"net/http"
)

func runtimeRoutes(m *http.ServeMux)                {}
func phpInventory(context.Context) []map[string]any { return []map[string]any{} }
