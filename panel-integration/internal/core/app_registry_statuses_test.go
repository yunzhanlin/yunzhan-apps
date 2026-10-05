package core

import (
	"context"
	"local/panel/internal/appcatalog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistrySlowRuntimeCannotEraseKnownModuleState(t *testing.T) {
	executor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtimes":
			<-r.Context().Done()
		case "/v1/software":
			_, _ = w.Write([]byte(`[{"id":"task-manager","installed":true,"healthy":true}]`))
		default:
			http.Error(w, `{"error":"probe unavailable"}`, 503)
		}
	}))
	defer executor.Close()
	address := strings.TrimPrefix(executor.URL, "http://")
	client := &ExecutorClient{Client: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}}}
	defer client.Client.CloseIdleConnections()
	server := &Server{Executor: client}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	rows := server.appRegistryStatuses(ctx, appcatalog.Catalog{Apps: []appcatalog.CatalogItem{
		{ID: "php-82", Stage: "ready", Provider: "runtime", Target: "php-8.2.33"},
		{ID: "task-manager", Stage: "ready", Provider: "panel-module", Target: "task-manager"},
		{ID: "mongodb", Stage: "ready", Provider: "compose", Target: "mongodb"},
	}})
	if rows[0].StateKnown || rows[2].StateKnown || !strings.Contains(rows[0].Detail, "未确认") {
		t.Fatal("failed probes were falsely reported as known-uninstalled", rows)
	}
	if !rows[1].StateKnown || !rows[1].Installed || !rows[1].Healthy {
		t.Fatal("slow runtime probe erased independent module evidence", rows)
	}
}
