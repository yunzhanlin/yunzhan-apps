package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

func TestDockerMetricsReviewRequiresExactInstalledEngine(t *testing.T) {
	spec, ok := runtimecatalog.DockerSpecOn("debian-13")
	if !ok {
		t.Fatal("missing Debian 13 Docker specification")
	}
	release, ok := runtimecatalog.Find(spec.ReleaseID)
	if !ok {
		t.Fatal("missing Docker release")
	}
	app := appcatalog.CatalogItem{ID: "docker-manager", Version: appcatalog.DockerMetricsVersion,
		Provider: "runtime", Target: "docker-auto", ManageRoute: "docker", SHA256: strings.Repeat("a", 64)}
	row := registryInstalledRuntime{ID: release.ID, Status: "installed", Family: release.Family, Version: release.Version}
	prior := registryReceipt{AppID: app.ID, Scope: release.ID, Version: "1-compat1", Target: app.Target, SHA256: strings.Repeat("b", 64)}
	for _, receipts := range []map[string]registryReceipt{nil, {app.ID + ":" + release.ID: prior}} {
		status := AppRegistryStatus{StateKnown: true}
		applyRegistryRuntimeStatus(&status, app, []registryInstalledRuntime{row}, receipts, "debian-13")
		if !status.Installed || !status.UpdateAvailable || status.UpdateKind != "docker-metrics-review" {
			t.Fatalf("exact installed Engine was not offered package-only review: %+v", status)
		}
	}
	row.ID = "docker-unknown"
	status := AppRegistryStatus{StateKnown: true}
	applyRegistryRuntimeStatus(&status, app, []registryInstalledRuntime{row}, nil, "debian-13")
	if status.UpdateKind == "docker-metrics-review" {
		t.Fatalf("a foreign Engine became eligible for the package review: %+v", status)
	}
}

func TestDockerMetricsReviewRecordsOnlyBoundObservation(t *testing.T) {
	spec, ok := runtimecatalog.DockerSpecOn(runtimecatalog.HostPlatform())
	if !ok {
		t.Skip("supported Docker host identity required")
	}
	release, ok := runtimecatalog.Find(spec.ReleaseID)
	if !ok {
		t.Fatal("missing Docker release")
	}
	store := testStore(t)
	var active atomic.Bool
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("package review submitted a host mutation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected method", 500)
			return
		}
		switch r.URL.Path {
		case "/v1/runtimes":
			_ = json.NewEncoder(w).Encode(map[string]any{"installed": []registryInstalledRuntime{{
				ID: release.ID, Family: "docker", Version: release.Version, Status: "installed",
			}}})
		case "/v1/docker":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": active.Load(), "active": active.Load(), "version": spec.EngineVersion})
		default:
			t.Errorf("unexpected package review probe: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	server := &Server{Store: store, Executor: executor}
	item := appcatalog.CatalogItem{ID: "docker-manager", Version: appcatalog.DockerMetricsVersion,
		Provider: "runtime", Target: "docker-auto", ManageRoute: "docker", SHA256: strings.Repeat("a", 64)}
	user := identity{ID: ID(), Username: "admin"}
	const key = "review-existing-docker"
	if _, err := server.reviewDockerMetricsPackage(context.Background(), item, key, user); err == nil {
		t.Fatal("inactive Engine received a completed package record")
	}
	active.Store(true)
	job, err := server.reviewDockerMetricsPackage(context.Background(), item, key, user)
	if err != nil {
		t.Fatal(err)
	}
	var kind, state, target string
	if err = store.DB.QueryRow("SELECT kind,state,target_id FROM runtime_jobs WHERE id=?", job).Scan(&kind, &state, &target); err != nil ||
		kind != dockerMetricsReviewJob || state != "succeeded" || target != release.ID {
		t.Fatalf("package review did not use a completed observation: %q %q %q %v", kind, state, target, err)
	}
	in := registryUpdateInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	replay, found, err := store.registryUpdateReplay(item.ID, user.ID, key, in)
	if err != nil || !found || replay.JobID != job {
		t.Fatalf("original package review was lost: %+v %v", replay, err)
	}
	if err = server.reconcileRegistryReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipts, err := store.registryReceipts()
	if err != nil || receipts[item.ID+":"+release.ID].Version != item.Version {
		t.Fatalf("verified package receipt missing: %+v %v", receipts, err)
	}
	if _, err = server.reviewDockerMetricsPackage(context.Background(), item, "other-key", user); err == nil {
		t.Fatal("already verified application package was recorded twice")
	}
	var jobs int
	if err = store.DB.QueryRow("SELECT count(*) FROM runtime_jobs").Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("review created additional host jobs: %d %v", jobs, err)
	}
}
