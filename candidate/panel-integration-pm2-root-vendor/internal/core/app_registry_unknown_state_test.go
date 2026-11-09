package core

import (
	"context"
	"local/panel/internal/appcatalog"
	"net/http"
	"strings"
	"testing"
)

func TestRegistryModuleMissingRowAndUntrustedRecordStayUnknown(t *testing.T) {
	for _, body := range []string{`[]`, `[{"id":"task-manager","state_unknown":true,"installed":false,"healthy":false,"detail":"private record refused"}]`, `[{"id":"task-manager","state_unknown":true,"installed":true,"healthy":true,"version":"1.0"}]`, `[{"id":"task-manager","installed":true,"healthy":true,"version":"1.0"},{"id":"task-manager","installed":true,"healthy":true,"version":"1.0"}]`} {
		executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/software" {
				w.Write([]byte(body))
				return
			}
			http.Error(w, "closed unrelated probe", 503)
		})
		server := &Server{Store: testStore(t), Executor: executor}
		rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "task-manager", Target: "task-manager", Provider: "panel-module", Stage: "ready", Version: "1.2.0"}}})
		if len(rows) != 1 || rows[0].StateKnown || rows[0].Installed || rows[0].Healthy || rows[0].VersionKnown || rows[0].UpdateAvailable || rows[0].UpdateSupported || !strings.Contains(rows[0].Detail, "未确认") {
			t.Fatal("missing/untrusted per-app record certified", rows)
		}
	}
}
