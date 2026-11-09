package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

// Discovery is not an install/update/migration authority. Keep package receipts
// distinct from upstream version inference and never mutate an old TCP project.
func TestMemcachedUnixCatalogKeepsExplicitLegacyMigrationVisible(t *testing.T) {
	if cmp, valid := appcatalog.CompareVersions("1.6.45", appcatalog.MemcachedUnixVersion); !valid || cmp != 1 {
		t.Fatal("do not weaken global semver to infer an application package")
	}
	project := strings.Repeat("a", 32)
	cases := []struct {
		name, app, target, latest, profile, receiptVersion, receiptProject string
		images                                                             []string
		unknown, update                                                    bool
	}{
		{name: "original-TCP-tag-without-receipt", images: []string{"memcached:1.6.45-alpine"}, update: true},
		{name: "original-TCP-digest-without-receipt", images: []string{appcatalog.MemcachedDigestImage}, update: true},
		{name: "old-compat2-receipt", receiptVersion: appcatalog.MemcachedDigestVersion, images: []string{appcatalog.MemcachedDigestImage}, update: true},
		{name: "old-compat1-receipt", receiptVersion: "1.6.45-compat1", images: []string{"memcached:1.6.45-alpine"}, update: true},
		{name: "another-project-receipt-cannot-hide-old-TCP", receiptVersion: appcatalog.MemcachedUnixVersion, receiptProject: strings.Repeat("b", 32), images: []string{appcatalog.MemcachedDigestImage}, update: true},
		{name: "current-Socket-package", profile: MemcachedUnixProfile, receiptVersion: appcatalog.MemcachedUnixVersion, images: []string{appcatalog.MemcachedDigestImage}},
		{name: "Socket-without-receipt-not-reinstalled", profile: MemcachedUnixProfile, images: []string{appcatalog.MemcachedDigestImage}},
		{name: "foreign-profile-not-adopted", profile: "custom-cache-v1", images: []string{appcatalog.MemcachedDigestImage}},
		{name: "newer-upstream-not-downgraded", images: []string{"memcached:1.6.46-alpine"}},
		{name: "unknown-image-digest-not-adopted", images: []string{"memcached:1.6.45-alpine@sha256:" + strings.Repeat("e", 64)}},
		{name: "multiple-images-not-adopted", images: []string{"memcached:1.6.45-alpine", "other:1.0"}},
		{name: "other-app-not-relabelled", app: "redis", images: []string{"memcached:1.6.45-alpine"}},
		{name: "other-template-not-adopted", target: "redis-cache", images: []string{"memcached:1.6.45-alpine"}},
		{name: "unknown-original-state-keeps-update-hidden", unknown: true, images: []string{"memcached:1.6.45-alpine"}},
		{name: "future-catalog-not-special-cased", latest: "1.6.45-compat5", images: []string{"memcached:1.6.45-alpine"}},
		{name: "plain-upstream-receipt-not-rewritten", receiptVersion: "1.6.45", images: []string{"memcached:1.6.45-alpine"}},
		{name: "newer-receipt-not-downgraded", receiptVersion: "1.6.45-compat5", images: []string{"memcached:1.6.45-alpine"}},
		{name: "old-digest-catalog-behavior-preserved", latest: appcatalog.MemcachedDigestVersion, images: []string{"memcached:1.6.45-alpine"}, update: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.app == "" {
				c.app = "memcached"
			}
			if c.target == "" {
				c.target = "memcached-cache"
			}
			if c.latest == "" {
				c.latest = appcatalog.MemcachedUnixVersion
			}
			s := testStore(t)
			if c.receiptVersion != "" {
				scope := c.receiptProject
				if scope == "" {
					scope = project
				}
				if _, e := s.DB.Exec("INSERT INTO app_registry_receipts VALUES('memcached',?,?,?,'memcached-cache',?)", scope, c.receiptVersion, strings.Repeat("f", 64), Now()); e != nil {
					t.Fatal(e)
				}
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("discovery issued a mutation", r.Method, r.URL.Path)
				}
				switch r.URL.Path {
				case "/v1/runtimes":
					w.Write([]byte("{\"installed\":[]}"))
				case "/v1/software":
					w.Write([]byte("[]"))
				case "/v1/docker/projects":
					json.NewEncoder(w).Encode(map[string]any{"projects": []any{map[string]any{"id": project, "template_id": c.target, "template_profile": c.profile, "state": "running", "state_known": !c.unknown, "services": 1, "running": 1, "healthy": 1, "images": c.images}}})
				default:
					t.Error("unexpected discovery endpoint", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			})
			server := &Server{Store: s, Executor: e}
			rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: c.app, Provider: "compose", Target: c.target, Stage: "ready", Version: c.latest}}})
			if len(rows) != 1 || rows[0].UpdateAvailable != c.update {
				t.Fatalf("hidden migration or unwanted duplicate/downgrade: %+v", rows)
			}
			v := rows[0]
			if c.latest == appcatalog.MemcachedUnixVersion && v.UpdateSupported {
				t.Fatal("migration/review granted automatic replacement", v)
			}
			if c.update {
				wantKind := "memcached-unix-migration"
				if c.latest == appcatalog.MemcachedDigestVersion {
					wantKind = "memcached-original"
				}
				if v.UpdateKind != wantKind || len(v.Instances) != 1 || !v.Instances[0].UpdateAvailable {
					t.Fatal("wrong original-instance review kind", v)
				}
				if c.latest == appcatalog.MemcachedUnixVersion && (!strings.Contains(v.UpdateDetail, "Socket") || !strings.Contains(v.UpdateDetail, "旧") || !strings.Contains(v.UpdateDetail, "不")) {
					t.Fatal("missing explicit non-replacement guidance", v.UpdateDetail)
				}
			}
			if c.receiptVersion == "" && !c.unknown && c.app == "memcached" && len(c.images) == 1 && !strings.Contains(c.images[0], "1.6.46") && (v.InstalledVersion != "1.6.45" || v.VersionSource != "upstream-image") {
				t.Fatal("upstream observation fabricated a package receipt", v)
			}
			for _, table := range []string{"runtime_jobs", "memcached_update_requests", "memcached_update_closures", "memcached_unix_controls", "audit_logs", "app_registry_pending", "app_registry_install_requests"} {
				var count int
				if e := s.DB.QueryRow("SELECT count(*)FROM " + table).Scan(&count); e != nil || count != 0 {
					t.Fatal("discovery changed original state", table, count, e)
				}
			}
			if c.receiptVersion != "" {
				var version string
				if e := s.DB.QueryRow("SELECT version FROM app_registry_receipts WHERE app_id='memcached'").Scan(&version); e != nil || version != c.receiptVersion {
					t.Fatal("original receipt rewritten", version, e)
				}
			}
		})
	}
}
