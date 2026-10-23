package core

import (
	"context"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func registryTestExecutor(t *testing.T, handler http.HandlerFunc) *ExecutorClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "http://")
	return &ExecutorClient{Client: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}}}
}

func TestRegistryDetectsActualInstalledVersionsAndOldRuntime(t *testing.T) {
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[{"id":"nginx-1.28.0","family":"nginx","version":"1.28.0","status":"installed"},{"id":"php-8.3.29","family":"php","version":"8.3.29","status":"installed"}]}`))
		case "/v1/software":
			w.Write([]byte(`[{"id":"files-sync","version":"1.0","installed":true,"healthy":true},{"id":"task-manager","version":"1.1.0","installed":true,"healthy":true}]`))
		case "/v1/docker/projects":
			w.Write([]byte(`{"projects":[{"id":"project-one","template_id":"memcached-cache","state":"running","services":1,"running":1,"healthy":1,"images":["memcached:1.6.40-alpine@sha256:abc"]}]}`))
		}
	})
	server := &Server{Store: testStore(t), Executor: executor}
	rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{
		{ID: "nginx", Version: "1.30.4-compat1", Provider: "runtime", Target: "nginx-1.30.4", Stage: "ready"},
		{ID: "php-84", Version: "8.4.25-compat1", Provider: "runtime", Target: "php-8.4.25", Stage: "ready"},
		{ID: "files-sync", Version: "1.1.0", Provider: "panel-module", Target: "files-sync", Stage: "ready"},
		{ID: "task-manager", Version: "1.1.0", Provider: "panel-module", Target: "task-manager", Stage: "ready"},
		{ID: "memcached", Version: "1.6.45-compat1", Provider: "compose", Target: "memcached-cache", Stage: "ready"},
	}})
	if !rows[0].Installed || !rows[0].UpdateAvailable || rows[0].InstalledVersion != "1.28.0" {
		t.Fatal("old runtime was mistaken for uninstalled", rows[0])
	}
	if rows[1].Installed {
		t.Fatal("a different PHP minor branch satisfied installation", rows[1])
	}
	if !rows[2].UpdateAvailable || rows[3].UpdateAvailable {
		t.Fatal("module update comparison incorrect", rows)
	}
	if !rows[4].UpdateAvailable || rows[4].UpdateSupported || rows[4].UpdateKind != "compose-review" {
		t.Fatal("unsafe container update advertised", rows[4])
	}
	if ValidateSoftwareUpdate("files-sync", "99.0.0") == nil || ValidateSoftwareUpdate("files-sync", "1.1.0") != nil {
		t.Fatal("missing implementation not guarded")
	}
}

func TestRegistryReceiptCommitsOnlySuccessfulJobs(t *testing.T) {
	store := testStore(t)
	server := &Server{Store: store}
	item := appcatalog.CatalogItem{ID: "files-sync", Version: "1.0", SHA256: strings.Repeat("1", 64), Provider: "panel-module", Target: "files-sync"}
	job, err := store.QueueSoftwareAction("files-sync", "install", nil, "first-job", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.trackRegistryJob(item, "files-sync", job); err != nil {
		t.Fatal(err)
	}
	if err = server.reconcileRegistryReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipts, _ := store.registryReceipts()
	if len(receipts) != 0 {
		t.Fatal("queued job pretended installed", receipts)
	}
	store.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job)
	if err = server.reconcileRegistryReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipts, _ = store.registryReceipts()
	if receipts["files-sync:files-sync"].Version != "1.0" {
		t.Fatal(receipts)
	}
	item.Version = "1.1.0"
	job, err = store.queueSoftwareAction("files-sync", "update", nil, item.Version, "second-job", "admin")
	if err != nil {
		t.Fatal(err)
	}
	store.trackRegistryJob(item, "files-sync", job)
	store.DB.Exec(`UPDATE runtime_jobs SET state='failed' WHERE id=?`, job)
	if err = server.reconcileRegistryReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipts, _ = store.registryReceipts()
	if receipts["files-sync:files-sync"].Version != "1.0" {
		t.Fatal("failed update changed version", receipts)
	}
	job, err = store.queueSoftwareAction("files-sync", "update", map[string]any{"danger": "reset"}, item.Version, "third-job", "admin")
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	store.DB.QueryRow(`SELECT payload FROM runtime_jobs WHERE id=?`, job).Scan(&raw)
	var payload map[string]any
	json.Unmarshal([]byte(raw), &payload)
	if payload["settings"] != nil || payload["version"] != "1.1.0" {
		t.Fatal("update replaced settings", payload)
	}
}
