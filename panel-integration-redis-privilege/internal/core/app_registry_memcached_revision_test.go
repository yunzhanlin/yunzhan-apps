package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestMemcachedLegacyImageWithoutPackageReceiptDoesNotHideExactDigestRevision(t *testing.T) {
	if cmp, valid := appcatalog.CompareVersions("1.6.45", appcatalog.MemcachedDigestVersion); !valid || cmp != 1 {
		t.Fatal("global semver rules were weakened to fix package provenance")
	}
	project := strings.Repeat("b", 32)
	for _, scenario := range []struct {
		name, version, target, receiptVersion, receiptProject string
		images                                                []string
		wantUpdate                                            bool
	}{
		{"actual-old-instance-no-receipt", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{"memcached:1.6.45-alpine"}, true},
		{"another-project-receipt-cannot-hide-this-instance", appcatalog.MemcachedDigestVersion, "memcached-cache", appcatalog.MemcachedDigestVersion, strings.Repeat("c", 32), []string{"memcached:1.6.45-alpine"}, true},
		{"old-real-package-receipt", appcatalog.MemcachedDigestVersion, "memcached-cache", "1.6.45-compat1", project, []string{"memcached:1.6.45-alpine"}, true},
		{"current-real-package-receipt", appcatalog.MemcachedDigestVersion, "memcached-cache", appcatalog.MemcachedDigestVersion, project, []string{appcatalog.MemcachedDigestImage}, false},
		{"newer-real-receipt-not-downgraded", appcatalog.MemcachedDigestVersion, "memcached-cache", "1.6.45-compat3", project, []string{"memcached:1.6.45-alpine"}, false},
		{"plain-upstream-real-receipt-not-reinterpreted", appcatalog.MemcachedDigestVersion, "memcached-cache", "1.6.45", project, []string{"memcached:1.6.45-alpine"}, false},
		{"newer-upstream-not-downgraded", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{"memcached:1.6.46-alpine"}, false},
		{"not-the-reviewed-legacy-image", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{"memcached:1.6.45-bookworm"}, false},
		{"unknown-digest-not-legacy-tag", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{"memcached:1.6.45-alpine@sha256:" + strings.Repeat("a", 64)}, false},
		{"already-pinned-image-not-recreated-without-receipt", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{appcatalog.MemcachedDigestImage}, false},
		{"ambiguous-multiple-images-not-admitted", appcatalog.MemcachedDigestVersion, "memcached-cache", "", "", []string{"memcached:1.6.45-alpine", "other:1.0"}, false},
		{"old-catalog-not-special-cased", "1.6.45-compat1", "memcached-cache", "", "", []string{"memcached:1.6.45-alpine"}, false},
		{"future-catalog-not-special-cased", "1.6.45-compat3", "memcached-cache", "", "", []string{"memcached:1.6.45-alpine"}, false},
		{"other-template-not-admitted", appcatalog.MemcachedDigestVersion, "unreviewed", "", "", []string{"memcached:1.6.45-alpine"}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s := testStore(t)
			if scenario.receiptVersion != "" {
				if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('memcached',?,?,?,'memcached-cache',?)`, scenario.receiptProject, scenario.receiptVersion, strings.Repeat("e", 64), Now()); err != nil {
					t.Fatal(err)
				}
			}
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("status discovery attempted a mutation", r.Method, r.URL.Path)
				}
				switch r.URL.Path {
				case "/v1/runtimes":
					w.Write([]byte(`{"installed":[]}`))
				case "/v1/software":
					w.Write([]byte(`[]`))
				case "/v1/docker/projects":
					json.NewEncoder(w).Encode(map[string]any{"projects": []any{map[string]any{"id": project, "template_id": scenario.target, "state": "running", "services": 1, "running": 1, "healthy": 1, "images": scenario.images}}})
				default:
					t.Error("status discovery made an unexpected call", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			})
			server := &Server{Store: s, Executor: executor}
			rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "memcached", Provider: "compose", Target: scenario.target, Stage: "ready", Version: scenario.version}}})
			if len(rows) != 1 || !rows[0].StateKnown || !rows[0].Installed || len(rows[0].Instances) != 1 || rows[0].UpdateAvailable != scenario.wantUpdate || rows[0].Instances[0].UpdateAvailable != scenario.wantUpdate {
				t.Fatalf("package revision hidden or unreviewed instance admitted: %+v", rows)
			}
			if scenario.wantUpdate && rows[0].UpdateKind != "memcached-original" {
				t.Fatal("did not retain explicit original-instance maintenance flow", rows[0])
			}
			if scenario.receiptVersion == "" || scenario.receiptProject != project {
				if rows[0].VersionSource != "upstream-image" || rows[0].Instances[0].VersionSource != "upstream-image" {
					t.Fatal("upstream inference was not distinguished from a package receipt", rows[0])
				}
				if rows[0].InstalledVersion != "1.6.45" && scenario.name != "newer-upstream-not-downgraded" {
					t.Fatal("an image was relabelled as a package receipt", rows[0])
				}
			} else if rows[0].VersionSource != "application-receipt" {
				t.Fatal("original receipt source lost", rows[0])
			}
			for _, table := range []string{"runtime_jobs", "memcached_update_requests", "memcached_update_closures", "audit_logs", "app_registry_pending"} {
				var count int
				if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatal("version discovery changed job/authority/receipt state", table, count, err)
				}
			}
		})
	}
}

func TestMemcachedMixedInstancesKeepOwnReceiptsAndOnlyReviewExactLegacy(t *testing.T) {
	s := testStore(t)
	current, legacy := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts VALUES('memcached',?,?,?,'memcached-cache',?)`, current, appcatalog.MemcachedDigestVersion, strings.Repeat("e", 64), Now()); err != nil {
		t.Fatal(err)
	}
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[]}`))
		case "/v1/software":
			w.Write([]byte(`[]`))
		case "/v1/docker/projects":
			json.NewEncoder(w).Encode(map[string]any{"projects": []any{
				map[string]any{"id": current, "template_id": "memcached-cache", "state": "running", "services": 1, "running": 1, "healthy": 1, "images": []string{appcatalog.MemcachedDigestImage}},
				map[string]any{"id": legacy, "template_id": "memcached-cache", "state": "running", "services": 1, "running": 1, "healthy": 1, "images": []string{"memcached:1.6.45-alpine"}},
			}})
		default:
			t.Error("discovery attempted an unexpected operation", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	})
	server := &Server{Store: s, Executor: executor}
	rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "memcached", Provider: "compose", Target: "memcached-cache", Stage: "ready", Version: appcatalog.MemcachedDigestVersion}}})
	if len(rows) != 1 || !rows[0].UpdateAvailable || rows[0].VersionKnown || rows[0].InstalledVersion != "" || len(rows[0].Instances) != 2 {
		t.Fatal("multiple instances were combined into one installed package version", rows)
	}
	for _, instance := range rows[0].Instances {
		if instance.ID == current {
			if instance.Version != appcatalog.MemcachedDigestVersion || instance.VersionSource != "application-receipt" || instance.UpdateAvailable {
				t.Fatal("current receipt was borrowed or changed", instance)
			}
		} else if instance.ID != legacy || instance.Version != "1.6.45" || instance.VersionSource != "upstream-image" || !instance.UpdateAvailable {
			t.Fatal("unreceipted legacy instance was hidden", instance)
		}
	}
}
