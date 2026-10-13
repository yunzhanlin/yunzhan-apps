package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func installReplayCounts(t *testing.T, s *Store) []int {
	t.Helper()
	out := []int{}
	for _, table := range []string{"runtime_jobs", "app_registry_install_requests", "app_registry_pending", "audit_logs"} {
		var n int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func installReplayFixture(t *testing.T, s *Store, key, actor string) (appcatalog.CatalogItem, registryInstallInput, string) {
	t.Helper()
	item := appcatalog.CatalogItem{ID: "load-balance", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64), Provider: "panel-module", Target: "load-balance"}
	in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	job, err := s.queueSoftwareActionBound(item.Target, "install", nil, "", key, "admin", s.bindRegistryInstall(item, item.Target, key, actor, in))
	if err != nil {
		t.Fatal(err)
	}
	return item, in, job
}

func installReplayHTTP(a *Server, app, key string, u identity, in registryInstallInput) *httptest.ResponseRecorder {
	body, _ := json.Marshal(in)
	r := httptest.NewRequest("POST", "/api/app-registry/"+app+"/install", strings.NewReader(string(body)))
	r.SetPathValue("id", app)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	a.installRegistryApp(w, r, u)
	return w
}

func TestRegistryInstallReplayAllModulesAtomicIdentity(t *testing.T) {
	for _, app := range SoftwareAppCatalog() {
		t.Run(app.ID, func(t *testing.T) {
			s := testStore(t)
			actor := ID()
			item := appcatalog.CatalogItem{ID: app.ID, Target: app.ID, Provider: "panel-module", Version: app.Version, SHA256: strings.Repeat("a", 64)}
			in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
			job, err := s.queueSoftwareActionBound(item.Target, "install", nil, "", "module-install", "admin", s.bindRegistryInstall(item, item.Target, "module-install", actor, in))
			if err != nil {
				t.Fatal(err)
			}
			if got := installReplayCounts(t, s); !reflect.DeepEqual(got, []int{1, 1, 1, 1}) {
				t.Fatal("queue and binding not atomic", got)
			}
			w := installReplayHTTP(&Server{Store: s}, item.ID, "module-install", identity{ID: actor}, in)
			if w.Code != 202 || !strings.Contains(w.Body.String(), job) {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestRegistryInstallReplayTerminalStatesReceiptRemovalAndReopen(t *testing.T) {
	for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "panel.db")
			s, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			actor := ID()
			item, in, job := installReplayFixture(t, s, "original", actor)
			if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, state, job); err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec(`DELETE FROM app_registry_pending WHERE job_id=?`, job); err != nil {
				t.Fatal(err)
			}
			before := installReplayCounts(t, s)
			if err = s.DB.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			// No catalog/executor exists. Nil/empty settings canonicalize equally.
			in.Settings = map[string]any{}
			w := installReplayHTTP(&Server{Store: s}, item.ID, "original", identity{ID: actor}, in)
			if w.Code != 202 || !strings.Contains(w.Body.String(), job) || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal(w.Code, w.Body.String(), "replay changed queue or bindings")
			}
			var got string
			if err = s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, job).Scan(&got); err != nil || got != state {
				t.Fatal("terminal/uncertain task retried", got, err)
			}
		})
	}
}

func TestRegistryInstallReplayIdentityPayloadAndMissingJobFailClosed(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item, in, job := installReplayFixture(t, s, "bound", actor)
	for _, test := range []struct {
		name, actor, app, key string
		input                 registryInstallInput
	}{
		{"actor", ID(), item.ID, "bound", in},
		{"app", actor, "daily-report", "bound", in},
		{"missing-key", actor, item.ID, "", in},
		{"spaces", actor, item.ID, " bound", in},
		{"long-key", actor, item.ID, strings.Repeat("x", 129), in},
		{"version", actor, item.ID, "bound", registryInstallInput{ExpectedVersion: "9.9.9", ExpectedSHA256: item.SHA256}},
		{"sha", actor, item.ID, "bound", registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: strings.Repeat("b", 64)}},
		{"settings", actor, item.ID, "bound", registryInstallInput{Settings: map[string]any{"enabled": true}, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}},
		{"name", actor, item.ID, "bound", registryInstallInput{Name: "other", ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}},
		{"port", actor, item.ID, "bound", registryInstallInput{HostPort: 21211, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := installReplayCounts(t, s)
			w := installReplayHTTP(&Server{Store: s}, test.app, test.key, identity{ID: test.actor}, test.input)
			if w.Code != 409 || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("unsafe replay accepted or changed queue", w.Code, w.Body.String())
			}
		})
	}
	for _, change := range []struct{ column, value string }{{"kind", "software_uninstall"}, {"target_id", "daily-report"}, {"payload", `{"settings":{"enabled":true},"version":""}`}, {"idempotency_key", "different"}} {
		t.Run(change.column, func(t *testing.T) {
			var old string
			if err := s.DB.QueryRow("SELECT "+change.column+" FROM runtime_jobs WHERE id=?", job).Scan(&old); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec("UPDATE runtime_jobs SET "+change.column+"=? WHERE id=?", change.value, job); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.registryInstallReplay(item.ID, actor, "bound", in); err == nil {
				t.Fatal("corrupted original job adopted")
			}
			if _, err := s.DB.Exec("UPDATE runtime_jobs SET "+change.column+"=? WHERE id=?", old, job); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := s.DB.Exec(`DELETE FROM runtime_jobs WHERE id=?`, job); err == nil {
		t.Fatal("FK discarded install identity")
	}
	// Simulate externally corrupted storage while retaining the binding. It must
	// not become a fresh request, even when foreign-key enforcement was bypassed.
	if _, err := s.DB.Exec(`PRAGMA foreign_keys=OFF; DELETE FROM runtime_jobs WHERE id='` + job + `'; PRAGMA foreign_keys=ON;`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.registryInstallReplay(item.ID, actor, "bound", in); err == nil {
		t.Fatal("missing original job reissued")
	}
}

func TestRegistryInstallBindingFaultAtomicRollbackAndNoLegacyAdoption(t *testing.T) {
	for _, table := range []string{"app_registry_install_requests", "app_registry_pending"} {
		t.Run(table, func(t *testing.T) {
			s := testStore(t)
			if _, err := s.DB.Exec("CREATE TRIGGER fail_install_binding BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'injected'); END;"); err != nil {
				t.Fatal(err)
			}
			item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Provider: "panel-module", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
			before := installReplayCounts(t, s)
			if _, err := s.queueSoftwareActionBound(item.Target, "install", nil, "", "fault", "admin", s.bindRegistryInstall(item, item.Target, "fault", ID(), registryInstallInput{})); err == nil || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("binding fault left orphan queued job/receipt/audit", err)
			}
		})
	}
	s := testStore(t)
	job, err := s.QueueSoftwareAction("load-balance", "install", nil, "legacy", "admin")
	if err != nil {
		t.Fatal(err)
	}
	item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Provider: "panel-module", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	before := installReplayCounts(t, s)
	if _, err = s.queueSoftwareActionBound(item.Target, "install", nil, "", "legacy", "admin", s.bindRegistryInstall(item, item.Target, "legacy", ID(), registryInstallInput{})); err == nil || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
		t.Fatal("unbound legacy/direct job adopted", job, err)
	}
}

func TestRegistryInstallConcurrentModuleBinding(t *testing.T) {
	s := testStore(t)
	u := identity{ID: ID(), Username: "admin"}
	item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Provider: "panel-module", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := s.queueSoftwareActionBound(item.Target, "install", nil, "", "parallel", u.Username, s.bindRegistryInstall(item, item.Target, "parallel", u.ID, registryInstallInput{}))
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
	job := ""
	for id := range ids {
		if job != "" && job != id {
			t.Fatal("parallel duplicate task", job, id)
		}
		job = id
	}
	if !reflect.DeepEqual(installReplayCounts(t, s), []int{1, 1, 1, 1}) {
		t.Fatal("parallel queue not atomic")
	}
}

func installSignedCatalog(t *testing.T, id, provider, target string) (*appcatalog.Client, appcatalog.CatalogItem) {
	t.Helper()
	manifest := appcatalog.Manifest{SchemaVersion: 1, ID: id, Name: id, Category: "deployment", Version: "1.0.0", Summary: "Bounded signed fixture for actual Core HTTP install tests", Stage: "ready", Risk: "normal", Delivery: appcatalog.Delivery{Provider: provider, Target: target, ManageRoute: "docker"}, Compatibility: appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}}, Capabilities: []string{"install"}}
	raw, _ := json.Marshal(manifest)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var item appcatalog.CatalogItem
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			catalog, _ := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: Now(), Apps: []appcatalog.CatalogItem{item}})
			json.NewEncoder(w).Encode(map[string]string{"catalog": string(catalog), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalog))})
		case "/dist/apps/" + id + "/1.0.0/manifest.json":
			w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	item = appcatalog.CatalogItem{ID: id, Name: id, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: "ready", Risk: manifest.Risk, Provider: provider, Target: target, ManageRoute: "docker", Capabilities: manifest.Capabilities, PackageURL: server.URL + "/dist/apps/" + id + "/1.0.0/manifest.json", SHA256: Hash(string(raw))}
	der, _ := x509.MarshalPKIXPublicKey(public)
	client, err := appcatalog.New(server.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client, item
}

func TestRegistryInstallComposeLostResponseQueriesFixedJobNeverResubmits(t *testing.T) {
	for _, observed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "accepted-but-response-lost"}[observed], func(t *testing.T) {
			s := testStore(t)
			catalog, item := installSignedCatalog(t, "memcached", "compose", "memcached-cache")
			var posts atomic.Int64
			var saved DockerProjectRequest
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					if r.URL.Path != "/v1/docker/projects/jobs" || json.NewDecoder(r.Body).Decode(&saved) != nil {
						t.Error("invalid Compose submission")
					}
					w.WriteHeader(500) // Delivery may have succeeded before reply loss.
					return
				}
				if r.Method != "GET" || r.URL.Path != "/v1/docker/jobs/"+saved.JobID {
					t.Error("replay queried different task", r.Method, r.URL.Path)
				}
				if !observed {
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(DockerJobResult{JobID: saved.JobID, ProjectID: saved.ProjectID, Kind: "compose", State: "failed"})
			})
			a := &Server{Store: s, AppCatalog: catalog, Executor: executor, Config: Config{DataDir: t.TempDir()}}
			u := identity{ID: ID(), Username: "admin"}
			in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
			w := installReplayHTTP(a, item.ID, "compose-fixed", u, in)
			want := 503
			if observed {
				want = 202
			}
			if w.Code != want || !strings.Contains(w.Body.String(), saved.JobID) || !strings.Contains(w.Body.String(), saved.ProjectID) {
				t.Fatal(w.Code, w.Body.String(), want)
			}
			before := installReplayCounts(t, s)
			a.AppCatalog = nil // Replays must not depend on remote catalog availability.
			for i := 0; i < 3; i++ {
				w = installReplayHTTP(a, item.ID, "compose-fixed", u, in)
				if w.Code != want || !strings.Contains(w.Body.String(), saved.JobID) {
					t.Fatal(w.Code, w.Body.String())
				}
			}
			if posts.Load() != 1 || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("uncertain/failed Compose install repeated mutation", posts.Load())
			}
			other := identity{ID: ID(), Username: "other"}
			if w := installReplayHTTP(a, item.ID, "compose-fixed", other, in); w.Code != 409 || posts.Load() != 1 {
				t.Fatal("cross-account Compose adoption", w.Code)
			}
		})
	}
}

func TestRegistryInstallReplayStillEnforcesHTTPPermissionsAndCSRF(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "install-owner", "admin", nil)
	other := accessUser(t, s, "install-other", "admin", nil)
	viewer := accessUser(t, s, "install-viewer", "viewer", nil)
	restricted := accessUser(t, s, "install-restricted", "admin", []string{"files"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	item, in, job := installReplayFixture(t, s, "http-install", owner.ID)
	a.AppCatalog, a.Executor = nil, nil
	call := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", "http-install")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	body, _ := json.Marshal(in)
	path := "/api/app-registry/" + item.ID + "/install"
	if w := call(path, string(body), "", nil); w.Code != 401 {
		t.Fatal("anonymous replay", w.Code)
	}
	for _, test := range []struct {
		name string
		want int
	}{{owner.Username, 202}, {other.Username, 409}, {viewer.Username, 403}, {restricted.Username, 403}} {
		w := call("/api/login", `{"username":"`+test.name+`","password":"access-test-password-long"}`, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var session accountSession
		if json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal("login reply")
		}
		cookie := w.Result().Cookies()[0]
		if w := call(path, string(body), "wrong", cookie); w.Code != 403 {
			t.Fatal("CSRF replay bypass", w.Code)
		}
		w = call(path, string(body), session.CSRF, cookie)
		if w.Code != test.want || (test.want == 202 && !strings.Contains(w.Body.String(), job)) {
			t.Fatal(test.name, w.Code, w.Body.String())
		}
	}
}

func TestRegistryInstallRuntimeBindingResolvedDockerTarget(t *testing.T) {
	for _, target := range []string{"nginx-1.30.4", "docker-auto"} {
		t.Run(target, func(t *testing.T) {
			s := testStore(t)
			actor := ID()
			scope := target
			if target == "docker-auto" {
				scope = "docker-fixed-reviewed-release"
			}
			item := appcatalog.CatalogItem{ID: "runtime-test", Provider: "runtime", Target: target, Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
			in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
			job := ID()
			tx, err := s.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,'install_runtime','succeeded','{}','runtime-install',?,?)`, job, scope, Now(), Now()); err != nil {
				t.Fatal(err)
			}
			if err = s.bindRegistryInstall(item, scope, "runtime-install", actor, in)(tx, job, false); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err = (&Server{Store: s}).reconcileRegistryReceipts(t.Context()); err != nil {
				t.Fatal(err)
			}
			before := installReplayCounts(t, s)
			prior, found, err := s.registryInstallReplay(item.ID, actor, "runtime-install", in)
			if err != nil || !found || prior.Scope != scope || prior.Target != target || prior.JobID != job || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("fixed runtime identity lost", prior, found, err)
			}
			if _, err = s.DB.Exec(`UPDATE app_registry_install_requests SET runtime_job_id=NULL WHERE job_id=?`, job); err == nil {
				t.Fatal("nullable CHECK admitted unbound runtime install")
			}
		})
	}
}

func TestRegistryInstallComposeConcurrentOriginalBodyDefaults(t *testing.T) {
	s := testStore(t)
	catalog, item := installSignedCatalog(t, "memcached", "compose", "memcached-cache")
	u := identity{ID: ID(), Username: "admin"}
	var posts atomic.Int64
	var mu sync.Mutex
	var saved DockerProjectRequest
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			posts.Add(1)
			if json.NewDecoder(r.Body).Decode(&saved) != nil {
				t.Error("invalid Compose request")
			}
			json.NewEncoder(w).Encode(DockerJobResult{JobID: saved.JobID, ProjectID: saved.ProjectID, Kind: "compose", State: "queued"})
			return
		}
		if saved.JobID == "" {
			http.NotFound(w, r) // Winning POST has not been observed yet.
			return
		}
		if r.Method != "GET" || r.URL.Path != "/v1/docker/jobs/"+saved.JobID {
			t.Error("duplicate install did not query original identity")
		}
		json.NewEncoder(w).Encode(DockerJobResult{JobID: saved.JobID, ProjectID: saved.ProjectID, Kind: "compose", State: "queued"})
	})
	a := &Server{Store: s, AppCatalog: catalog, Executor: executor, Config: Config{DataDir: t.TempDir()}}
	in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- installReplayHTTP(a, item.ID, "parallel-compose", u, in).Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 202 && code != 503 { // Unobserved dispatch must not be called queued.
			t.Fatal("original/defaulted request identity changed", code)
		}
	}
	if posts.Load() != 1 {
		t.Fatal("concurrent Compose duplicate projects", posts.Load())
	}
	got := installReplayCounts(t, s)
	if got[0] != 0 || got[1] != 1 || got[2] != 1 {
		t.Fatal("Compose reservation duplicated", got)
	}
}

func TestRegistryInstallComposeReservationFaultNeverCallsExecutor(t *testing.T) {
	for _, table := range []string{"app_registry_install_requests", "app_registry_pending"} {
		t.Run(table, func(t *testing.T) {
			s := testStore(t)
			if _, err := s.DB.Exec("CREATE TRIGGER fail_compose_reserve BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'injected'); END;"); err != nil {
				t.Fatal(err)
			}
			catalog, item := installSignedCatalog(t, "memcached", "compose", "memcached-cache")
			var calls atomic.Int64
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
			a := &Server{Store: s, AppCatalog: catalog, Executor: executor, Config: Config{DataDir: t.TempDir()}}
			w := installReplayHTTP(a, item.ID, "reservation-fault", identity{ID: ID(), Username: "admin"}, registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
			got := installReplayCounts(t, s)
			if w.Code != 409 || calls.Load() != 0 || got[0] != 0 || got[1] != 0 || got[2] != 0 {
				t.Fatal("reservation fault reached executor or left orphan", w.Code, calls.Load(), got)
			}
		})
	}
}
