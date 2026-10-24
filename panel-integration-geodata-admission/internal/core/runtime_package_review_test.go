package core

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

// Status-model regression only; not an installed app or update receipt.
func TestRegistryRuntimeWithoutPackageReceiptDoesNotHidePackageRevision(t *testing.T) {
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[{"id":"nginx-1.30.6","family":"nginx","version":"1.30.6","status":"installed"}]}`))
		case "/v1/software":
			w.Write([]byte(`[]`))
		case "/v1/docker/projects":
			w.Write([]byte(`{"projects":[]}`))
		default:
			t.Errorf("status requested an unexpected native operation: %s %s", r.Method, r.URL.Path)
		}
	})
	s := &Server{Store: testStore(t), Executor: executor}
	rows := s.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "nginx", Version: "1.30.6-compat2", Provider: "runtime", Target: "nginx-1.30.6", Stage: "ready"}}})
	if len(rows) != 1 || !rows[0].StateKnown || !rows[0].Installed || rows[0].InstalledVersion != "1.30.6" || !rows[0].UpdateAvailable {
		t.Fatal("upstream binary version was incorrectly used as proof that a signed package revision was already applied", rows)
	}
}

func TestRegistryRuntimeProgramAndReceiptNamespacesAreSeparate(t *testing.T) {
	app := appcatalog.CatalogItem{ID: "nginx", Version: "1.30.6-compat2", SHA256: strings.Repeat("a", 64), Provider: "runtime", Target: "nginx-1.30.6", Stage: "ready"}
	current := registryInstalledRuntime{ID: app.Target, Family: "nginx", Version: "1.30.6", Status: "installed"}
	receipt := registryReceipt{AppID: app.ID, Scope: app.Target, Version: app.Version, SHA256: app.SHA256, Target: app.Target}
	old := current
	old.ID, old.Version = "nginx-1.30.4", "1.30.4"
	newer := current
	newer.ID, newer.Version = "nginx-1.31.5", "1.31.5"
	system := current
	system.ID = "nginx-system"
	for _, tc := range []struct {
		name                             string
		rows                             []registryInstalledRuntime
		record                           *registryReceipt
		change                           func(*registryReceipt)
		known, installed, update, review bool
		version, source                  string
	}{
		{name: "no-receipt", rows: []registryInstalledRuntime{current}, known: true, installed: true, update: true, review: true, version: current.Version, source: "upstream-runtime"},
		{name: "current-real-receipt", rows: []registryInstalledRuntime{current}, record: &receipt, known: true, installed: true, version: app.Version, source: "application-receipt"},
		{name: "older-package", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Version = "1.30.6-compat1" }, known: true, installed: true, update: true, version: "1.30.6-compat1", source: "application-receipt"},
		{name: "newer-package-not-downgraded", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Version = "1.30.6-compat3" }, known: true, installed: true, version: "1.30.6-compat3", source: "application-receipt"},
		{name: "real-plain-package-not-reinterpreted-as-program", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Version = "1.30.6" }, known: true, installed: true, version: "1.30.6", source: "application-receipt"},
		{name: "older-native-program", rows: []registryInstalledRuntime{old}, known: true, installed: true, update: true, version: old.Version, source: "upstream-runtime"},
		{name: "system-program-without-native-package", rows: []registryInstalledRuntime{system}, known: true, installed: true, update: true, review: true, version: system.Version, source: "upstream-runtime"},
		{name: "newer-native-program-not-downgraded", rows: []registryInstalledRuntime{newer}, known: true, installed: true, version: newer.Version, source: "upstream-runtime"},
		{name: "newer-coexisting-program-wins-over-old-package", rows: []registryInstalledRuntime{current, newer}, record: &receipt, change: func(r *registryReceipt) { r.Version = "1.30.6-compat1" }, known: true, installed: true, version: newer.Version, source: "upstream-runtime"},
		{name: "equal-system-alias-cannot-hide-real-package-revision", rows: []registryInstalledRuntime{system, current}, record: &receipt, change: func(r *registryReceipt) { r.Version = "1.30.6-compat1" }, known: true, installed: true, update: true, version: "1.30.6-compat1", source: "application-receipt"},
		{name: "stale-receipt-cannot-invent-an-install", record: &receipt, known: true},
		{name: "duplicate-current-runtime", rows: []registryInstalledRuntime{current, current}},
		{name: "foreign-receipt-target", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Target = old.ID }},
		{name: "foreign-receipt-app", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.AppID = "apache" }},
		{name: "foreign-receipt-scope", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Scope = old.ID }},
		{name: "invalid-receipt-version", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.Version = "unknown" }},
		{name: "invalid-receipt-digest", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.SHA256 = "" }},
		{name: "uppercase-receipt-digest", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.SHA256 = strings.Repeat("A", 64) }},
		{name: "same-package-version-different-digest", rows: []registryInstalledRuntime{current}, record: &receipt, change: func(r *registryReceipt) { r.SHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := map[string]registryReceipt{}
			if tc.record != nil {
				v := *tc.record
				if tc.change != nil {
					tc.change(&v)
				}
				records[app.ID+":"+app.Target] = v
			}
			before, _ := json.Marshal(records)
			state := AppRegistryStatus{StateKnown: true}
			applyRegistryRuntimeStatus(&state, app, tc.rows, records, "debian-13")
			if state.StateKnown != tc.known || tc.known && (state.Installed != tc.installed || state.UpdateAvailable != tc.update || (state.UpdateKind == "runtime-package-review") != tc.review || state.InstalledVersion != tc.version || state.VersionSource != tc.source) {
				t.Fatal("runtime and package namespaces mixed", state)
			}
			after, _ := json.Marshal(records)
			if string(before) != string(after) {
				t.Fatal("status fabricated or rewrote receipt")
			}
		})
	}
}

func TestRegistryRuntimeUnknownProgramOrBranchCannotGrantReview(t *testing.T) {
	for _, tc := range []struct {
		name, id, target, version, family, observed string
		known, installed                            bool
	}{
		{"wrong-native-version", "nginx", "nginx-1.30.6", "1.30.6-compat2", "nginx", "1.30.4", false, false},
		{"wrong-native-family", "nginx", "nginx-1.30.6", "1.30.6-compat2", "apache", "1.30.6", false, false},
		{"malformed-program-version", "nginx", "nginx-1.30.6", "1.30.6-compat2", "nginx", "unknown", false, false},
		{"wrong-php-minor-exact-id", "php-85", "php-8.5.10", "8.5.10-compat2", "php", "8.4.25", false, false},
		{"other-php-minor-is-not-this-app", "php-85", "php-8.5.10", "8.5.10-compat2", "php", "8.4.25", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := registryInstalledRuntime{ID: tc.target, Family: tc.family, Version: tc.observed, Status: "installed"}
			if strings.HasPrefix(tc.name, "other-") {
				row.ID = "php-8.4.25"
			}
			state := AppRegistryStatus{StateKnown: true}
			applyRegistryRuntimeStatus(&state, appcatalog.CatalogItem{ID: tc.id, Target: tc.target, Version: tc.version}, []registryInstalledRuntime{row}, nil, "debian-13")
			if state.StateKnown != tc.known || state.Installed != tc.installed || state.UpdateAvailable {
				t.Fatal("unknown native identity granted review", state)
			}
		})
	}
}

func TestRegistryRuntimeDockerAutoUsesActualPlatformTargetNotPackageMajor(t *testing.T) {
	app := appcatalog.CatalogItem{ID: "docker-manager", Target: "docker-auto", Version: "1-compat1", SHA256: strings.Repeat("a", 64)}
	row := registryInstalledRuntime{ID: "docker-debian-26.1.5", Family: "docker", Version: "26.1.5", Status: "installed"}
	state := AppRegistryStatus{StateKnown: true}
	applyRegistryRuntimeStatus(&state, app, []registryInstalledRuntime{row}, nil, "debian-13")
	if !state.UpdateAvailable || state.UpdateKind != "runtime-package-review" || state.InstalledVersion != "26.1.5" {
		t.Fatal("opaque Docker package revision compared with engine version", state)
	}
	record := registryReceipt{AppID: app.ID, Scope: row.ID, Target: "docker-auto", Version: app.Version, SHA256: app.SHA256}
	state = AppRegistryStatus{StateKnown: true}
	applyRegistryRuntimeStatus(&state, app, []registryInstalledRuntime{row}, map[string]registryReceipt{app.ID + ":" + row.ID: record}, "debian-13")
	if !state.StateKnown || state.UpdateAvailable || state.VersionSource != "application-receipt" || state.InstalledVersion != app.Version {
		t.Fatal("bound resolved Docker receipt lost", state)
	}
}

func TestRegistryRuntimeReadStatusNeverWritesJobsAuditsOrReceipts(t *testing.T) {
	store := testStore(t)
	before := replayCounts(t, store)
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("read status submitted native mutation", r.Method, r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1/runtimes":
			w.Write([]byte(`{"installed":[{"id":"nginx-1.30.6","family":"nginx","version":"1.30.6","status":"installed"}]}`))
		case "/v1/software":
			w.Write([]byte(`[]`))
		case "/v1/docker/projects":
			w.Write([]byte(`{"projects":[]}`))
		default:
			t.Error("unexpected operation", r.URL.Path)
		}
	})
	server := &Server{Store: store, Executor: executor}
	catalog := appcatalog.Catalog{Apps: []appcatalog.CatalogItem{{ID: "nginx", Target: "nginx-1.30.6", Version: "1.30.6-compat2", Provider: "runtime", Stage: "ready"}}}
	wantKind := "runtime-package-review"
	if supported, _ := registrySupportOn(catalog.Apps[0], runtimecatalog.HostPlatform(), runtime.GOARCH); !supported {
		wantKind = "panel-upgrade"
	}
	for range 3 {
		rows := server.appRegistryStatuses(context.Background(), catalog)
		if len(rows) != 1 || !rows[0].UpdateAvailable || rows[0].VersionSource != "upstream-runtime" || rows[0].UpdateKind != wantKind {
			t.Fatal(rows)
		}
	}
	var receipts int
	if err := store.DB.QueryRow(`SELECT count(*) FROM app_registry_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("read status created an application receipt", receipts, err)
	}
	after := replayCounts(t, store)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("read status changed original ledger", before, after)
	}
}
