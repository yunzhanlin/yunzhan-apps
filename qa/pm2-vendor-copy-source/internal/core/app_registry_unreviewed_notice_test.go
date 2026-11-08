package core

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

func TestRegistryUnreviewedRuntimeAnnouncesNewerProgramWithoutApprovingIt(t *testing.T) {
	for _, item := range []struct{ id, old, next string }{
		{"php-82", "8.2.33", "8.2.99"},
		{"php-83", "8.3.33", "8.3.99"},
		{"php-84", "8.4.25", "8.4.99"},
		{"php-85", "8.5.10", "8.5.99"},
	} {
		t.Run(item.id, func(t *testing.T) {
			app := appcatalog.CatalogItem{ID: item.id, Provider: "runtime", Target: "php-" + item.next, Version: item.next + "-compat1", Stage: "ready"}
			if _, known := runtimecatalog.Find(app.Target); known {
				t.Fatal("This fixture must remain an unreviewed announcement")
			}
			rows := []registryInstalledRuntime{{ID: "php-" + item.old, Family: "php", Version: item.old, Status: "installed"}}
			receipts := map[string]registryReceipt{item.id + ":php-" + item.old: {AppID: item.id, Scope: "php-" + item.old, Target: "php-" + item.old, Version: item.old + "-compat1", SHA256: strings.Repeat("a", 64)}}
			before, _ := json.Marshal(receipts)
			state := AppRegistryStatus{StateKnown: true}
			applyRegistryRuntimeStatus(&state, app, rows, receipts, "debian-13")
			if !state.StateKnown || !state.Installed || !state.UpdateAvailable || state.UpdateSupported || state.UpdateKind != "panel-upgrade" || state.InstalledVersion != item.old || state.VersionSource != "upstream-runtime" {
				t.Fatal("Future program announcement was hidden or treated as an approved package", state)
			}
			after, _ := json.Marshal(receipts)
			if string(before) != string(after) {
				t.Fatal("Informational notice changed existing receipt")
			}
		})
	}
}

func TestRegistryUnreviewedRuntimeVersionNoticeIsNotPackageRevisionComparisonOrDowngrade(t *testing.T) {
	app := appcatalog.CatalogItem{ID: "nginx", Provider: "runtime", Target: "nginx-9.99.99", Version: "9.99.99-compat1"}
	for _, observed := range []struct {
		version string
		update  bool
	}{{"1.31.5", true}, {"9.99.99", false}, {"10.0.0", false}} {
		state := AppRegistryStatus{StateKnown: true}
		applyRegistryRuntimeStatus(&state, app, []registryInstalledRuntime{{ID: "nginx-system", Family: "nginx", Version: observed.version, Status: "installed"}}, nil, "debian-13")
		if state.UpdateAvailable != observed.update || state.UpdateSupported || state.InstalledVersion != observed.version || state.VersionSource != "upstream-runtime" {
			t.Fatal("Unreviewed target granted a receipt/review, compared package revision with program, or offered downgrade", state)
		}
	}
	state := AppRegistryStatus{StateKnown: true}
	applyRegistryRuntimeStatus(&state, app, nil, map[string]registryReceipt{app.ID + ":" + app.Target: {AppID: app.ID, Scope: app.Target, Target: app.Target, Version: app.Version, SHA256: strings.Repeat("a", 64)}}, "debian-13")
	if state.Installed || state.UpdateAvailable {
		t.Fatal("Stale receipt invented installed future software", state)
	}
}

func TestRegistryUnreviewedAnnouncementRequiresExactCanonicalAppTargetAndLabel(t *testing.T) {
	app := appcatalog.CatalogItem{ID: "php-85", Provider: "runtime", Target: "php-8.5.12", Version: "8.5.12-compat1"}
	if v, ok := announcedUnreviewedRuntimeVersion(app, "php"); !ok || v != "8.5.12" {
		t.Fatal("Exact announcement identity not recognized")
	}
	for name, mutate := range map[string]func(*appcatalog.CatalogItem){
		"foreign-provider":            func(a *appcatalog.CatalogItem) { a.Provider = "compose" },
		"foreign-app":                 func(a *appcatalog.CatalogItem) { a.ID = "php-84" },
		"foreign-family":              func(a *appcatalog.CatalogItem) { a.Target = "mysql-8.5.12" },
		"foreign-minor":               func(a *appcatalog.CatalogItem) { a.Target, a.Version = "php-8.4.27", "8.4.27-compat1" },
		"unrelated-package-label":     func(a *appcatalog.CatalogItem) { a.Version = "99.0.0-compat1" },
		"unsupported-revision-format": func(a *appcatalog.CatalogItem) { a.Version = "8.5.12-other1" },
		"empty-revision":              func(a *appcatalog.CatalogItem) { a.Version = "8.5.12-compat" },
		"revision-alias":              func(a *appcatalog.CatalogItem) { a.Version = "8.5.12-compat01" },
		"version-alias":               func(a *appcatalog.CatalogItem) { a.Target, a.Version = "php-08.5.12", "08.5.12-compat1" },
		"overflow": func(a *appcatalog.CatalogItem) {
			a.Target, a.Version = "php-8.5.18446744073709551616", "8.5.18446744073709551616-compat1"
		},
		"newline":    func(a *appcatalog.CatalogItem) { a.Target += "\n" },
		"prerelease": func(a *appcatalog.CatalogItem) { a.Target, a.Version = "php-8.5.12-rc1", "8.5.12-rc1" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := app
			mutate(&bad)
			if _, ok := announcedUnreviewedRuntimeVersion(bad, "php"); ok {
				t.Fatal("Unreviewed malformed/foreign identity became a program update", bad)
			}
		})
	}
}

func TestRegistryUnreviewedRuntimeFullStatusShowsPanelUpgradeAndNeverQueuesOrWrites(t *testing.T) {
	store := testStore(t)
	before := replayCounts(t, store)
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatal("Status read dispatched native mutation", r.Method, r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[{"id":"php-8.5.10","family":"php","version":"8.5.10","status":"installed"}]}`))
		case "/v1/software":
			w.Write([]byte(`[]`))
		case "/v1/docker/projects":
			w.Write([]byte(`{"projects":[]}`))
		default:
			t.Fatal("Unexpected native operation", r.URL.Path)
		}
	})
	server := &Server{Store: store, Executor: executor}
	catalog := appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "php-85", Provider: "runtime", Target: "php-8.5.99", Version: "8.5.99-compat1", Stage: "ready"}}}
	for range 3 {
		rows := server.appRegistryStatuses(context.Background(), catalog)
		if len(rows) != 1 || !rows[0].Installed || !rows[0].StateKnown || !rows[0].UpdateAvailable || rows[0].Supported || rows[0].UpdateSupported || rows[0].UpdateKind != "panel-upgrade" {
			t.Fatal("Missing safe informational update state", rows)
		}
	}
	if !reflect.DeepEqual(before, replayCounts(t, store)) {
		t.Fatal("Read-only future-runtime notice changed original ledgers")
	}
	var receipts int
	if err := store.DB.QueryRow("SELECT count(*) FROM app_registry_receipts").Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("Status read created a receipt", receipts, err)
	}
}
