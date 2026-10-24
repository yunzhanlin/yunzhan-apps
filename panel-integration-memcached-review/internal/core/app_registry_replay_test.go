package core

import (
	"encoding/json"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func registryReplayFixture(t *testing.T, s *Store, key, actorID string) (appcatalog.CatalogItem, string) {
	t.Helper()
	item := appcatalog.CatalogItem{ID: "load-balance", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64), Provider: "panel-module", Target: "load-balance"}
	job, err := s.queueSoftwareActionBound(item.Target, "update", nil, item.Version, key, "admin", s.bindRegistryUpdate(item, item.Target, key, actorID))
	if err != nil {
		t.Fatal(err)
	}
	return item, job
}
func replayCounts(t *testing.T, s *Store) []int {
	t.Helper()
	out := []int{}
	for _, table := range []string{"runtime_jobs", "app_registry_update_requests", "app_registry_pending", "audit_logs"} {
		var n int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}
func TestRegistryUpdateReplayAfterCompletionAndReceiptRemoval(t *testing.T) {
	for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention"} {
		t.Run(state, func(t *testing.T) {
			s := testStore(t)
			actor := ID()
			item, job := registryReplayFixture(t, s, "request", actor)
			if _, err := s.DB.Exec("UPDATE runtime_jobs SET state=? WHERE id=?", state, job); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec("DELETE FROM app_registry_pending WHERE job_id=?", job); err != nil {
				t.Fatal(err)
			}
			before := replayCounts(t, s)
			server := &Server{Store: s} // No catalog or executor: replay must not fetch or execute.
			req := httptest.NewRequest("POST", "/api/app-registry/load-balance/update", strings.NewReader(`{"expected_version":"`+item.Version+`","expected_sha256":"`+item.SHA256+`"}`))
			req.Header.Set("Idempotency-Key", "request")
			req.SetPathValue("id", item.ID)
			w := httptest.NewRecorder()
			server.updateRegistryApp(w, req, identity{ID: actor, Username: "admin"})
			var out registryUpdateReplay
			var response map[string]string
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response["job_id"] != job || response["provider"] != item.Provider {
				t.Fatal(w.Code, w.Body.String(), out)
			}
			after := replayCounts(t, s)
			for i, n := range before {
				if n != after[i] {
					t.Fatal("replay mutated queue/binding/receipt/audit", before, after)
				}
			}
			var actual string
			_ = s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", job).Scan(&actual)
			if actual != state {
				t.Fatal("replay retried terminal/uncertain job", actual)
			}
		})
	}
}
func TestRegistryUpdateReplayRejectsDifferentIdentityAndCorruptJobs(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item, job := registryReplayFixture(t, s, "same-key", actor)
	in := registryUpdateInput{item.Version, item.SHA256}
	for _, test := range []struct {
		name, app, actor, key string
		input                 registryUpdateInput
	}{
		{"actor", item.ID, ID(), "same-key", in},
		{"app", "daily-report", actor, "same-key", in},
		{"version", item.ID, actor, "same-key", registryUpdateInput{"9.9.9", item.SHA256}},
		{"sha", item.ID, actor, "same-key", registryUpdateInput{item.Version, strings.Repeat("b", 64)}},
		{"empty-key", item.ID, actor, "", in},
		{"long-key", item.ID, actor, strings.Repeat("x", 129), in},
		{"spaces", item.ID, actor, " same-key", in},
		{"uppercase-sha", item.ID, actor, "same-key", registryUpdateInput{item.Version, strings.Repeat("A", 64)}},
		{"invalid-version", item.ID, actor, "same-key", registryUpdateInput{"../1", item.SHA256}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := s.registryUpdateReplay(test.app, test.actor, test.key, test.input); err == nil {
				t.Fatal("unsafe replay accepted")
			}
		})
	}
	for _, change := range []struct{ column, value string }{
		{"target_id", "daily-report"}, {"kind", "software_uninstall"}, {"payload", `{"settings":{},"version":"` + item.Version + `"}`}, {"idempotency_key", "changed"},
	} {
		t.Run(change.column, func(t *testing.T) {
			var old string
			if err := s.DB.QueryRow("SELECT "+change.column+" FROM runtime_jobs WHERE id=?", job).Scan(&old); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec("UPDATE runtime_jobs SET "+change.column+"=? WHERE id=?", change.value, job); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.registryUpdateReplay(item.ID, actor, "same-key", in); err == nil {
				t.Fatal("corrupted job accepted")
			}
			if _, err := s.DB.Exec("UPDATE runtime_jobs SET "+change.column+"=? WHERE id=?", old, job); err != nil {
				t.Fatal(err)
			}
		})
	}
	// FK prevents forgetting an idempotency identity through job deletion.
	if _, err := s.DB.Exec("DELETE FROM runtime_jobs WHERE id=?", job); err == nil {
		t.Fatal("durable replay identity discarded")
	}
}
func TestRegistryUpdateBindingFailureRollsBackAllQueueState(t *testing.T) {
	for _, table := range []string{"app_registry_update_requests", "app_registry_pending"} {
		t.Run(table, func(t *testing.T) {
			s := testStore(t)
			if _, err := s.DB.Exec("CREATE TRIGGER fail_registry_binding BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'injected binding failure'); END;"); err != nil {
				t.Fatal(err)
			}
			item := appcatalog.CatalogItem{ID: "load-balance", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64), Provider: "panel-module", Target: "load-balance"}
			before := replayCounts(t, s)
			if _, err := s.queueSoftwareActionBound(item.Target, "update", nil, item.Version, "failing", "admin", s.bindRegistryUpdate(item, item.Target, "failing", ID())); err == nil {
				t.Fatal("fault ignored")
			}
			after := replayCounts(t, s)
			for i, n := range before {
				if n != after[i] {
					t.Fatal("orphan queued job or binding", before, after)
				}
			}
		})
	}
}
func TestRegistryUpdateConcurrentBindingAndUnboundKeyRejection(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item := appcatalog.CatalogItem{ID: "load-balance", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64), Provider: "panel-module", Target: "load-balance"}
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := s.queueSoftwareActionBound(item.Target, "update", nil, item.Version, "concurrent", "admin", s.bindRegistryUpdate(item, item.Target, "concurrent", actor))
			if err != nil {
				errs <- err
			} else {
				ids <- job
			}
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	expected := ""
	count := 0
	for job := range ids {
		count++
		if expected == "" {
			expected = job
		}
		if job != expected {
			t.Fatal("duplicate queue", expected, job)
		}
	}
	if count != 16 {
		t.Fatal(count)
	}
	counts := replayCounts(t, s)
	if counts[0] != 1 || counts[1] != 1 || counts[2] != 1 || counts[3] != 1 {
		t.Fatal("bindings not atomic", counts)
	}
	if _, err := s.queueSoftwareActionBound(item.Target, "update", nil, item.Version, "concurrent", "other", s.bindRegistryUpdate(item, item.Target, "concurrent", ID())); err == nil {
		t.Fatal("another user adopted existing job")
	}
	other := testStore(t)
	old, err := other.queueSoftwareAction(item.Target, "update", nil, item.Version, "unbound", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.queueSoftwareActionBound(item.Target, "update", nil, item.Version, "unbound", "admin", other.bindRegistryUpdate(item, item.Target, "unbound", actor)); err == nil {
		t.Fatal("unbound direct lifecycle job adopted")
	}
	var n int
	_ = other.DB.QueryRow("SELECT count(*) FROM app_registry_update_requests").Scan(&n)
	if n != 0 {
		t.Fatal("failed adoption left a binding")
	}
	var state string
	_ = other.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", old).Scan(&state)
	if state != "queued" {
		t.Fatal("original job changed")
	}
}
func TestRegistryUpdateRuntimeBindingAndReceipt(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item := appcatalog.CatalogItem{ID: "nginx", Version: "1.30.4-compat1", SHA256: strings.Repeat("c", 64), Provider: "runtime", Target: "nginx-1.30.4"}
	job, err := s.queueInstallBound(item.Target, "runtime-bound", "admin", s.bindRegistryUpdate(item, item.Target, "runtime-bound", actor))
	if err != nil {
		t.Fatal(err)
	}
	prior, found, err := s.registryUpdateReplay(item.ID, actor, "runtime-bound", registryUpdateInput{item.Version, item.SHA256})
	if err != nil || !found || prior.JobID != job || prior.Provider != "runtime" {
		t.Fatal(prior, found, err)
	}
	if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job); err != nil {
		t.Fatal(err)
	}
	a := &Server{Store: s}
	if err = a.reconcileRegistryReceipts(t.Context()); err != nil {
		t.Fatal(err)
	}
	receipts, err := s.registryReceipts()
	if err != nil || receipts["nginx:"+item.Target].Version != item.Version {
		t.Fatal(receipts, err)
	}
	prior, found, err = s.registryUpdateReplay(item.ID, actor, "runtime-bound", registryUpdateInput{item.Version, item.SHA256})
	if err != nil || !found || prior.JobID != job {
		t.Fatal("receipt reconciliation forgot replay", prior, err)
	}
}

func TestRegistryUpdateReplayStillEnforcesHTTPPermissionsAndCSRF(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "replay-owner", "admin", nil)
	other := accessUser(t, s, "replay-other", "admin", nil)
	viewer := accessUser(t, s, "replay-viewer", "viewer", nil)
	restricted := accessUser(t, s, "replay-restricted", "admin", []string{"files"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	item, job := registryReplayFixture(t, s, "http-replay", owner.ID)
	_, err = s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job)
	if err != nil {
		t.Fatal(err)
	}
	a.AppCatalog = nil
	a.Executor = nil // A genuine replay should not need either dependency.
	call := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", a.Config.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Idempotency-Key", "http-replay")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := call("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var session accountSession
		if json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal("session")
		}
		return w.Result().Cookies()[0], session.CSRF
	}
	body := `{"expected_version":"` + item.Version + `","expected_sha256":"` + item.SHA256 + `"}`
	cookie, csrf := login(owner.Username)
	if w := call("/api/app-registry/load-balance/update", body, "wrong", cookie); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if w := call("/api/app-registry/load-balance/update", body, csrf, cookie); w.Code != 202 || !strings.Contains(w.Body.String(), job) {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie, csrf = login(other.Username)
	if w := call("/api/app-registry/load-balance/update", body, csrf, cookie); w.Code != 409 {
		t.Fatal("different account replay", w.Code)
	}
	cookie, csrf = login(viewer.Username)
	if w := call("/api/app-registry/load-balance/update", body, csrf, cookie); w.Code != 403 {
		t.Fatal("viewer replay permission bypass", w.Code)
	}
	cookie, csrf = login(restricted.Username)
	if w := call("/api/app-registry/load-balance/update", body, csrf, cookie); w.Code != 403 {
		t.Fatal("restricted administrator replay permission bypass", w.Code)
	}
}
