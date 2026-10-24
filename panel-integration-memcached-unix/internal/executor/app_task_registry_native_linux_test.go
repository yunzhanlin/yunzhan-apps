//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const taskNativeManifestSHA = "210dc302db5f1c87915a3f20dc96d5c94232cfbd66da229e50ae30e9c7be0600"

type taskNativePackageTransport struct {
	body  []byte
	calls atomic.Int32
}

func (p *taskNativePackageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "GET" || r.URL.String() != appcatalog.DefaultBaseURL+"/dist/apps/task-manager/1.2.0/manifest.json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Context().Err() != nil {
		return nil, errors.New("private Task fixture excludes every other repository read")
	}
	p.calls.Add(1)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(p.body)), ContentLength: int64(len(p.body)), Request: r}, nil
}

// Called only by the explicit owned kernel fixture. Exact existing official
// catalog/package bytes, real default trust key, Core auth and worker, real
// Unix executor and SQLite Finish/reconciliation. The package is a signed-catalog
// bound panel-module manifest; its implementation is in the normal signed panel.
// This does not download arbitrary plugin code or claim live GitHub/cold boot.
func taskNativeSignedRegistryInstall(t *testing.T, ctx context.Context, base string, panel *core.Server, store *core.Store, svc *Service, cookie *http.Cookie, csrf string, installs *atomic.Int32, entered <-chan struct{}, release func()) {
	t.Helper()
	bundle, err := os.ReadFile(filepath.Join(base, "catalog-v1.bundle.json"))
	if err != nil || core.Hash(string(bundle)) != "c7e4925bb34c7f626e3eefa023be3d939aaae2f865069c6b85ffc6de804e965c" {
		t.Fatal("exact official Task catalog bytes", err)
	}
	manifest, err := os.ReadFile(filepath.Join(base, "task-manifest.json"))
	if err != nil || core.Hash(string(manifest)) != taskNativeManifestSHA {
		t.Fatal("exact official Task manifest bytes", err)
	}
	cache := filepath.Join(base, "data/app-registry/catalog")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(cache, "catalog-v1.bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	transport := &taskNativePackageTransport{body: manifest}
	panel.AppCatalog = appcatalog.Default()
	panel.AppCatalog.HTTP = &http.Client{Transport: transport, Timeout: 2 * time.Second}
	catalog, info, err := panel.AppCatalog.LoadCatalog(ctx, cache, time.Minute)
	item, found := appcatalog.Find(catalog, "task-manager")
	if err != nil || info.Source != "verified-cache" || len(catalog.Apps) != 50 || !found || item.SHA256 != taskNativeManifestSHA || item.Version != "1.2.0" || item.Provider != "panel-module" || item.Target != "task-manager" {
		t.Fatal("actual default-key Task catalog validation", err)
	}
	request := func(method, path, key string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, method, panel.Config.Origin+path, bytes.NewReader(body))
		r.Header.Set("Origin", panel.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	registry := func() core.AppRegistryStatus {
		t.Helper()
		w := request("GET", "/api/app-registry", "", nil)
		var out core.AppRegistryPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Source.Source != "verified-cache" {
			t.Fatal("actual Task registry status", w.Code)
		}
		for _, row := range out.Status {
			if row.ID == "task-manager" {
				return row
			}
		}
		t.Fatal("missing Task registry row")
		return core.AppRegistryStatus{}
	}
	receipts := func() int {
		t.Helper()
		var count int
		if err := store.DB.QueryRow(`SELECT count(*) FROM app_registry_receipts WHERE app_id='task-manager'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if row := registry(); !row.StateKnown || row.Installed || receipts() != 0 || svc.moduleInstalled("task-manager") {
		t.Fatal("Task was fabricated as installed before queue")
	}
	body, _ := json.Marshal(map[string]any{"expected_version": item.Version, "expected_sha256": item.SHA256, "settings": map[string]any{}})
	queue := func(key string) string {
		t.Helper()
		w := request("POST", "/api/app-registry/task-manager/install", key, body)
		var out struct {
			Job      string `json:"job_id"`
			Provider string `json:"provider"`
			Target   string `json:"target"`
		}
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !core.ValidID(out.Job) || out.Provider != "panel-module" || out.Target != "task-manager" {
			t.Fatal("actual original Task install queue", w.Code)
		}
		return out.Job
	}
	state := func(job string) string {
		t.Helper()
		var state, kind, target string
		if err := store.DB.QueryRow(`SELECT state,kind,target_id FROM runtime_jobs WHERE id=?`, job).Scan(&state, &kind, &target); err != nil || kind != "software_install" || target != "task-manager" {
			t.Fatal("actual original Task install identity", err)
		}
		return state
	}
	wait := func(job, want string) {
		t.Helper()
		for ctx.Err() == nil {
			got := state(job)
			if got == want {
				return
			}
			if got != "queued" && got != "running" {
				t.Fatal("actual Task job failed or unexpectedly succeeded", got, want)
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Millisecond):
			}
		}
		t.Fatal("Task install exceeded original child context", ctx.Err())
	}
	// Real filesystem refusal, not a fabricated failed executor response. The
	// symlink is a newly created private fixture pointing only inside this base.
	module := svc.moduleDir("task-manager")
	if err := os.MkdirAll(filepath.Dir(module), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "task-own-outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("owned-private-task-sentinel\n")
	if err := atomicWrite(filepath.Join(outside, "sentinel"), sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, module); err != nil {
		t.Fatal(err)
	}
	linkInfo, err := os.Lstat(module)
	if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("fresh own link fixture unavailable", err)
	}
	bad := queue("native-task-failed-install")
	if state(bad) != "queued" || receipts() != 0 || installs.Load() != 0 {
		t.Fatal("queued failure was treated as an installation")
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { core.RunWorker(workerCtx, store, panel.Executor); close(done) }()
	defer func() {
		release()
		stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("own Task Core worker did not stop")
		}
	}()
	wait(bad, "failed")
	if row := registry(); row.Installed || receipts() != 0 || svc.moduleInstalled("task-manager") || installs.Load() != 1 {
		t.Fatal("real failed Task write created an installed receipt")
	}
	firstPulls := transport.calls.Load()
	if firstPulls != 1 || queue("native-task-failed-install") != bad || installs.Load() != 1 || transport.calls.Load() != firstPulls {
		t.Fatal("failed original request fetched or executed again", installs.Load(), transport.calls.Load())
	}
	st, err := os.Lstat(module)
	link, linkErr := os.Readlink(module)
	if err != nil || st.Mode()&os.ModeSymlink == 0 || !os.SameFile(st, linkInfo) || linkErr != nil || link != outside {
		t.Fatal("own failed fixture identity changed")
	}
	if raw, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || !bytes.Equal(raw, sentinel) {
		t.Fatal("failed install modified the private sentinel")
	}
	if _, err := os.Lstat(filepath.Join(outside, "installed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed install wrote into symlink target")
	}
	// Remove only the exact fresh fixture link, never the target or user data.
	if err := os.Remove(module); err != nil {
		t.Fatal(err)
	}
	// The first attempt already verified and stored the exact official package.
	// A distinct request must work using that cache even with the remote offline.
	transport.body = nil
	good := queue("native-task-original-install")
	if got := state(good); got != "queued" && got != "running" || receipts() != 0 {
		t.Fatal("positive queue invented a receipt")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual install handler not reached", ctx.Err())
	}
	if state(good) != "running" || svc.moduleInstalled("task-manager") || receipts() != 0 || registry().Installed {
		t.Fatal("blocked pre-write install was certified")
	}
	release()
	wait(good, "succeeded")
	row := registry()
	if !row.StateKnown || !row.Installed || !row.Healthy || !row.VersionKnown || row.InstalledVersion != item.Version || receipts() != 1 || !svc.moduleInstalled("task-manager") || installs.Load() != 2 {
		t.Fatal("actual completed Task install/receipt not verified", row)
	}
	var receiptVersion, receiptSHA, receiptTarget string
	if err := store.DB.QueryRow(`SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='task-manager'`).Scan(&receiptVersion, &receiptSHA, &receiptTarget); err != nil || receiptVersion != item.Version || receiptSHA != item.SHA256 || receiptTarget != "task-manager" {
		t.Fatal("actual receipt lost signed package binding", err)
	}
	installed := filepath.Join(module, "installed.json")
	before, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(installed)
	if err != nil {
		t.Fatal(err)
	}
	if queue("native-task-original-install") != good || installs.Load() != 2 || transport.calls.Load() != firstPulls {
		t.Fatal("completed original install replay fetched or executed again", installs.Load(), transport.calls.Load())
	}
	after, err := os.ReadFile(installed)
	afterInfo, statErr := os.Lstat(installed)
	if err != nil || statErr != nil || !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("completed replay rewrote installed Task record")
	}
	// Real cache owner and mode refusals through the authenticated Core route.
	// Change only these fresh owned fixture records, never the user's cache.
	packagePath := filepath.Join(cache, "..", "packages", item.ID, item.Version, "manifest.json")
	packageInfo, err := os.Lstat(packagePath)
	if err != nil || !packageInfo.Mode().IsRegular() || packageInfo.Mode().Perm() != 0600 {
		t.Fatal("actual cache record unavailable", err)
	}
	owner, ok := packageInfo.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		t.Fatal("actual private cache owner unavailable")
	}
	var marker struct {
		UID int `json:"uid"`
	}
	markerBytes, err := os.ReadFile(filepath.Join(base, "fixture.json"))
	if err != nil || json.Unmarshal(markerBytes, &marker) != nil || marker.UID <= 0 {
		t.Fatal("original own numeric child UID unavailable")
	}
	denyCache := func(key string) {
		t.Helper()
		w := request("POST", "/api/app-registry/task-manager/install", key, body)
		var jobs, bindings int
		if err := store.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&jobs); err != nil {
			t.Fatal(err)
		}
		if err := store.DB.QueryRow(`SELECT count(*) FROM app_registry_install_requests`).Scan(&bindings); err != nil {
			t.Fatal(err)
		}
		if w.Code != 409 || jobs != 2 || bindings != 2 || receipts() != 1 || installs.Load() != 2 || transport.calls.Load() != firstPulls {
			t.Fatal("untrusted private cache created a pull/job/receipt/execution", w.Code, jobs, bindings, installs.Load(), transport.calls.Load())
		}
		if queue("native-task-original-install") != good || installs.Load() != 2 || transport.calls.Load() != firstPulls {
			t.Fatal("immutable original replay depended on untrusted cache or reexecuted")
		}
	}
	func() {
		if err := os.Chmod(packagePath, 0644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(packagePath, packageInfo.Mode().Perm()); err != nil {
				t.Error(err)
			}
		}()
		denyCache("native-task-public-cache-file")
	}()
	versionDir := filepath.Dir(packagePath)
	func() {
		if err := os.Chmod(versionDir, 0755); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(versionDir, 0700); err != nil {
				t.Error(err)
			}
		}()
		denyCache("native-task-public-cache-parent")
	}()
	func() {
		if err := os.Chown(packagePath, marker.UID, int(owner.Gid)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chown(packagePath, int(owner.Uid), int(owner.Gid)); err != nil {
				t.Error(err)
			}
		}()
		denyCache("native-task-foreign-cache-owner")
	}()
	packageAfter, err := os.Lstat(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	packageAfterOwner, ownerOK := packageAfter.Sys().(*syscall.Stat_t)
	if !ownerOK || !os.SameFile(packageInfo, packageAfter) || packageAfter.Mode().Perm() != packageInfo.Mode().Perm() || packageAfterOwner.Uid != owner.Uid || packageAfterOwner.Gid != owner.Gid {
		t.Fatal("own cache refusal tests did not restore exact identity/permissions/owner")
	}
	if err := moduleWrite(filepath.Join(base, "core-cache-acceptance.json"), map[string]any{
		"passed": true, "actual_authenticated_core_offline_verified_cache_reused": true,
		"actual_public_file_and_parent_and_foreign_owner_refused":                      true,
		"refusals_preserve_original_request_and_have_no_pull_job_receipt_or_execution": true,
		"own_cache_identity_permissions_and_owner_restored":                            true,
		"exact_manifest_pulls": firstPulls, "cold_boot_verified": false, "all_50_commercial": false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := moduleWrite(filepath.Join(base, "core-registry-install-acceptance.json"), map[string]any{"passed": true, "official_default_key_catalog_verified": true, "manifest_sha256": taskNativeManifestSHA, "manifest_is_signed_catalog_bound_panel_module_metadata_not_arbitrary_plugin_code": true, "actual_authenticated_core_worker_unix_executor_sqlite_finish_and_status_reconciliation": true, "actual_failed_filesystem_write_has_no_install_receipt": true, "actual_queued_running_prewrite_have_no_install_receipt": true, "actual_original_failed_and_completed_replays_do_not_reexecute": true, "actual_private_sentinel_and_installed_record_identity_preserved": true, "failed_job_id": bad, "installed_job_id": good, "actual_executor_install_attempts": installs.Load(), "exact_manifest_pulls": transport.calls.Load(), "actual_installed_version": row.InstalledVersion, "actual_receipt_sha256": receiptSHA, "live_github_verified": false, "browser_verified": false, "cold_boot_verified": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual official Task signed-catalog package via authenticated Core/worker/Unix executor/SQLite Finish and receipt reconciliation; real private symlink write refusal, queued/running not installed, failed/completed original replays no reexecution; offline transport and builtin code in signed panel, not live GitHub/Chrome/cold boot")
}
