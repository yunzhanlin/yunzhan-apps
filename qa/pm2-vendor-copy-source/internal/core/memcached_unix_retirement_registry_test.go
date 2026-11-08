package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestMemcachedUnixRetiredDiscoveryKeepsReceiptsButDoesNotInventALiveInstall(t *testing.T) {
	project, live := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, kind := range []string{"retired-only", "retired-and-live", "unknown-retirement", "missing-known", "contradictory-running-count"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			if _, e := s.DB.Exec("INSERT INTO app_registry_receipts VALUES('memcached',?,?,?,'memcached-cache',?)", project, appcatalog.MemcachedUnixVersion, strings.Repeat("c", 64), Now()); e != nil {
				t.Fatal(e)
			}
			record := map[string]any{"id": project, "template_id": "memcached-cache", "template_profile": MemcachedUnixProfile, "state": "retired", "state_known": true, "services": 0, "running": 0, "healthy": 0, "images": []string{appcatalog.MemcachedDigestImage}}
			if kind == "unknown-retirement" {
				record["state_known"] = false
			}
			if kind == "missing-known" {
				delete(record, "state_known")
			}
			if kind == "contradictory-running-count" {
				record["running"] = 1
			}
			projects := []any{record}
			if kind == "retired-and-live" {
				projects = append(projects, map[string]any{"id": live, "template_id": "memcached-cache", "state": "running", "services": 1, "running": 1, "healthy": 1, "images": []string{"memcached:1.6.45-alpine"}})
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("discovery mutation", r.Method)
				}
				switch r.URL.Path {
				case "/v1/runtimes":
					w.Write([]byte("{\"installed\":[]}"))
				case "/v1/software":
					w.Write([]byte("[]"))
				case "/v1/docker/projects":
					json.NewEncoder(w).Encode(map[string]any{"projects": projects})
				default:
					t.Error("unexpected discovery", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			})
			rows := (&Server{Store: s, Executor: e}).appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "memcached", Provider: "compose", Target: "memcached-cache", Version: appcatalog.MemcachedUnixVersion, Stage: "ready"}}})
			if len(rows) != 1 {
				t.Fatal(rows)
			}
			v := rows[0]
			if kind == "retired-only" {
				if !v.StateKnown || v.Installed || v.Healthy || v.VersionKnown || v.UpdateAvailable || len(v.Instances) != 0 {
					t.Fatal("retirement became a live installation", v)
				}
			} else if kind == "retired-and-live" {
				if !v.StateKnown || !v.Installed || !v.Healthy || !v.UpdateAvailable || v.UpdateKind != "memcached-unix-migration" || len(v.Instances) != 1 || v.Instances[0].ID != live {
					t.Fatal("retired history erased or impersonated another live project", v)
				}
			} else if v.StateKnown || v.Installed || v.Healthy || v.UpdateAvailable {
				t.Fatal("unproved retirement became known-uninstalled or healthy", v)
			}
			var version string
			if e := s.DB.QueryRow("SELECT version FROM app_registry_receipts WHERE app_id='memcached' AND scope=?", project).Scan(&version); e != nil || version != appcatalog.MemcachedUnixVersion {
				t.Fatal("historical install receipt deleted/relabelled", version, e)
			}
			for _, table := range []string{"audit_logs", "runtime_jobs", "app_registry_pending", "memcached_unix_controls"} {
				var count int
				if e := s.DB.QueryRow("SELECT count(*)FROM " + table).Scan(&count); e != nil || count != 0 {
					t.Fatal("discovery wrote", table, count, e)
				}
			}
		})
	}
}
