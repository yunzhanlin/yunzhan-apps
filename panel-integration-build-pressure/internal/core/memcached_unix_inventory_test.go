package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestMemcachedUnixInventoryUnknownIsNotHealthyUninstalledOrOtherAppFailure(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain-original", true: "verified-stopped"}[known], func(t *testing.T) {
			s := testStore(t)
			project := strings.Repeat("a", 32)
			if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('memcached',?,?,?,'memcached-cache',?)`, project, appcatalog.MemcachedUnixVersion, strings.Repeat("e", 64), Now()); err != nil {
				t.Fatal(err)
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("discovery mutation", r.Method, r.URL.Path)
				}
				switch r.URL.Path {
				case "/v1/runtimes":
					w.Write([]byte(`{"installed":[]}`))
				case "/v1/software":
					w.Write([]byte(`[]`))
				case "/v1/docker/projects":
					json.NewEncoder(w).Encode(map[string]any{"projects": []any{
						map[string]any{"id": project, "template_id": "memcached-cache", "state": "stopped", "state_known": known, "services": 1, "running": 0, "healthy": 0, "images": []string{appcatalog.MemcachedDigestImage}},
						map[string]any{"id": strings.Repeat("b", 32), "template_id": "mongodb", "state": "running", "services": 1, "running": 1, "healthy": 1, "images": []string{"mongo:8.0"}},
					}})
				default:
					t.Error("unexpected discovery", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			})
			rows := (&Server{Store: s, Executor: e}).appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{
				{ID: "memcached", Version: appcatalog.MemcachedUnixVersion, Provider: "compose", Target: "memcached-cache", Stage: "ready"},
				{ID: "mongodb", Version: "8.0.0", Provider: "compose", Target: "mongodb", Stage: "ready"},
			}})
			if len(rows) != 2 || rows[0].Healthy || rows[0].StateKnown != known || rows[0].Installed != known || rows[0].VersionKnown != known || rows[0].UpdateAvailable {
				t.Fatal("unknown/stopped cache was reported ready or available for duplicate install", rows)
			}
			if !rows[1].StateKnown || !rows[1].Installed || !rows[1].Healthy {
				t.Fatal("one uncertain Socket instance erased another app's actual state", rows[1])
			}
		})
	}
}
