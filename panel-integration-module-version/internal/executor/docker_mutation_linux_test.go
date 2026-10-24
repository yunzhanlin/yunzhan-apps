//go:build linux

package executor

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Actual Linux Root file descriptors/flocks, but no daemon operation, service
// action, installed application, installer lock or production path is changed.
func dockerMutationFixture(t *testing.T) dockerMutationStore {
	t.Helper()
	base, _ := memcachedPlanFileFixture(t)
	state := filepath.Join(filepath.Dir(base), "state")
	if os.Mkdir(state, 0700) != nil || os.Mkdir(filepath.Join(state, "docker-jobs"), 0700) != nil {
		t.Fatal("private mutation fixture")
	}
	if err := os.WriteFile(filepath.Join(state, "runtime-lifecycle.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return dockerMutationStore{state: state, blocked: func() bool { return false }, pending: func(context.Context) error { return nil }}
}

func TestDockerMutationSharedRuntimeAndComposeLeasesSerializeAcrossDescriptors(t *testing.T) {
	s := dockerMutationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	l, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f, err := os.OpenFile(filepath.Join(s.state, "runtime-lifecycle.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("program mutation EX lease coexisted with Docker", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal("unrelated readonly runtime user was denied", err)
	}
	unix.Flock(int(f.Fd()), unix.LOCK_UN)
	short, done := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer done()
	if other, err := s.begin(short); err == nil {
		other.Close()
		t.Fatal("two Docker/Compose owners")
	}
	var count int
	var bound context.Context
	if err := l.use(ctx, func(c context.Context) error {
		bound = c
		return withDockerMutation(c, func(context.Context) error { count++; return nil })
	}); err != nil || count != 1 {
		t.Fatal("nested native callback did not retain original capability", err, count)
	}
	before, err := os.Lstat(filepath.Join(s.state, "docker-jobs/compose.lock"))
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if withDockerMutation(bound, func(context.Context) error { count++; return nil }) == nil || count != 1 {
		t.Fatal("closed original capability reacquired a replacement")
	}
	second, err := s.begin(ctx)
	if err != nil {
		t.Fatal("settled lease not released", err)
	}
	second.Close()
	after, err := os.Lstat(filepath.Join(s.state, "docker-jobs/compose.lock"))
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("lease file recreated or rewritten", err)
	}
}

func TestDockerMutationCloseCannotReleaseAnInFlightNativeCallback(t *testing.T) {
	s := dockerMutationFixture(t)
	l, err := s.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- l.use(context.Background(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	go func() { l.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("exclusive Docker lease closed before native callback finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	<-closed
	if l.use(context.Background(), func(context.Context) error { t.Fatal("closed callback executed"); return nil }) == nil {
		t.Fatal("closed lease adopted")
	}
}

func TestDockerMutationCancellationMarkerAndOriginalDirectoryDriftPreventNextEffect(t *testing.T) {
	for _, scenario := range []string{"canceled", "marker", "detached-state", "replaced-runtime", "replaced-compose"} {
		t.Run(scenario, func(t *testing.T) {
			s := dockerMutationFixture(t)
			var blocked atomic.Bool
			s.blocked = blocked.Load
			l, err := s.begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "canceled":
				cancel()
			case "marker":
				blocked.Store(true)
			case "detached-state":
				if err := os.Rename(s.state, s.state+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(s.state, 0700); err != nil {
					t.Fatal(err)
				}
			case "replaced-runtime", "replaced-compose":
				p := filepath.Join(s.state, "runtime-lifecycle.lock")
				if scenario == "replaced-compose" {
					p = filepath.Join(s.state, "docker-jobs/compose.lock")
				}
				if err := os.Rename(p, p+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			if err := l.use(ctx, func(context.Context) error { called = true; return nil }); err == nil || called {
				t.Fatal("changed original lease allowed a new effect", err)
			}
		})
	}
}

func TestDockerMutationUnsafeExistingFilesAndParentsNeverRepaired(t *testing.T) {
	for _, scenario := range []string{"missing-runtime", "public-runtime", "nonempty-runtime", "hardlink-runtime", "symlink-runtime", "fifo-runtime", "foreign-runtime", "public-jobs", "symlink-jobs", "writable-state", "public-compose", "nonempty-compose", "foreign-compose"} {
		t.Run(scenario, func(t *testing.T) {
			s := dockerMutationFixture(t)
			runtime := filepath.Join(s.state, "runtime-lifecycle.lock")
			lock := filepath.Join(s.state, "docker-jobs/compose.lock")
			switch scenario {
			case "missing-runtime":
				if err := os.Remove(runtime); err != nil {
					t.Fatal(err)
				}
			case "public-runtime":
				if err := os.Chmod(runtime, 0644); err != nil {
					t.Fatal(err)
				}
			case "nonempty-runtime":
				if err := os.WriteFile(runtime, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink-runtime":
				if err := os.Link(runtime, runtime+".original"); err != nil {
					t.Fatal(err)
				}
			case "symlink-runtime", "fifo-runtime":
				if err := os.Rename(runtime, runtime+".original"); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink-runtime" {
					if err := os.Symlink("runtime-lifecycle.lock.original", runtime); err != nil {
						t.Fatal(err)
					}
				} else if err := unix.Mkfifo(runtime, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-runtime":
				if err := os.Chown(runtime, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "public-jobs":
				if err := os.Chmod(filepath.Dir(lock), 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-jobs":
				if err := os.Rename(filepath.Dir(lock), filepath.Dir(lock)+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("docker-jobs-original", filepath.Dir(lock)); err != nil {
					t.Fatal(err)
				}
			case "writable-state":
				if err := os.Chmod(s.state, 0777); err != nil {
					t.Fatal(err)
				}
			case "public-compose", "nonempty-compose", "foreign-compose":
				if err := os.WriteFile(lock, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "public-compose" {
					if err := os.Chmod(lock, 0644); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "nonempty-compose" {
					if err := os.WriteFile(lock, []byte("retained"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "foreign-compose" {
					if err := os.Chown(lock, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			}
			beforeRuntime, e1 := os.Lstat(runtime)
			beforeLock, e2 := os.Lstat(lock)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			if l, err := s.begin(ctx); err == nil {
				l.Close()
				t.Fatal("unsafe fixture admitted native mutation")
			}
			afterRuntime, e3 := os.Lstat(runtime)
			afterLock, e4 := os.Lstat(lock)
			if os.IsNotExist(e1) != os.IsNotExist(e3) || os.IsNotExist(e2) != os.IsNotExist(e4) || e1 == nil && !geoStoreStableInfo(beforeRuntime, afterRuntime) || e2 == nil && !geoStoreStableInfo(beforeLock, afterLock) {
				t.Fatal("existing file repaired, created or overwritten")
			}
		})
	}
}

func TestDockerMutationRealUnverifiedJournalAndUnknownPendingPolicyBlock(t *testing.T) {
	for _, scenario := range []string{"nil-policy", "unknown-policy", "original-prepared-journal", "original-unsigned-terminal"} {
		t.Run(scenario, func(t *testing.T) {
			s := dockerMutationFixture(t)
			switch scenario {
			case "nil-policy":
				s.pending = nil
			case "unknown-policy":
				s.pending = func(context.Context) error { return errors.New("original observation unknown") }
			default:
				store, seed := memcachedJournalFixture(t)
				j := memcachedJournalPrepare(t, store, seed)
				if scenario == "original-unsigned-terminal" {
					lease, err := j.lease()
					if err != nil {
						t.Fatal(err)
					}
					if err := lease.append(memcachedJournalNext(t, seed.Record, "failed_safe")); err != nil {
						t.Fatal(err)
					}
					lease.Close()
				}
				s.pending = store.checkProgramUpgrade
			}
			if l, err := s.begin(context.Background()); err == nil {
				l.Close()
				t.Fatal("unknown or unsigned state let generic Docker operations erase rollback material")
			}
		})
	}
}

func TestDockerMutationHTTPReadOnlyAndNestedOwnedMutationAreDistinct(t *testing.T) {
	s := dockerMutationFixture(t)
	l, err := s.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var count int
	h := dockerMutationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := withDockerMutation(r.Context(), func(context.Context) error { count++; return nil }); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(204)
	}))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		r := httptest.NewRequest(method, "/v1/docker/projects", nil)
		if method == http.MethodPost {
			r = r.WithContext(context.WithValue(r.Context(), dockerMutationContextKey{}, l))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(method, w.Code, w.Body.String())
		}
	}
	if count != 1 {
		t.Fatal("unexpected native callbacks", count)
	}
	l.Close()
	for _, r := range []*http.Request{httptest.NewRequest(http.MethodPost, "/v1/docker/containers/abc/restart", nil), httptest.NewRequest(http.MethodGet, "/v1/docker/jobs/abc", nil)} {
		r = r.WithContext(context.WithValue(r.Context(), dockerMutationContextKey{}, l))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 409 || w.Header().Get("Cache-Control") != "no-store" || count != 1 {
			t.Fatal("closed mutation or legacy reconciling GET bypassed barrier", w.Code)
		}
	}
}

func TestDockerMutationClosedCapabilityRefusesEveryNativeWriterBeforeIO(t *testing.T) {
	s := dockerMutationFixture(t)
	l, err := s.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), dockerMutationContextKey{}, l)
	l.Close()
	// Invalid inert native arguments are a second safety boundary if the
	// guard regresses; they must never reach a daemon/CLI in this test.
	if _, err := dockerRequest(ctx, http.MethodPost, "/this-is-not-a-Docker-operation", nil, nil, 1024); !errors.Is(err, errDockerMutation) {
		t.Fatal("REST writer escaped the closed original lease", err)
	}
	if err := dockerPull(ctx, "invalid??image"); !errors.Is(err, errDockerMutation) {
		t.Fatal("streaming pull escaped the closed original lease", err)
	}
	if _, err := composeCommand(ctx, "__guard_native_effect_must_not_run__"); !errors.Is(err, errDockerMutation) {
		t.Fatal("Compose native command escaped the closed original lease", err)
	}
}

var dockerMutationNativeGuards = flag.Bool("docker-mutation-native-guards", false, "explicit owned Linux QA fixed-path HTTP/lease denial checks; never performs a valid Docker mutation")

func TestDockerMutationProductionHTTPInvalidEffectAndInstallerConflictReadonlyQA(t *testing.T) {
	if !*dockerMutationNativeGuards {
		t.Skip("explicit owned QA target required; no production lock or API guessed")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual Linux Root required")
	}
	state := productionDockerMutationStore()
	if state.state != "/var/lib/panel-executor" {
		t.Fatal("production path changed")
	}
	tree, err := openDockerMutationTree(state.state)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	// Require BOTH original files already present. This test is not lock-file
	// setup/migration, and it must not create any actual production file.
	before := map[string]os.FileInfo{}
	for _, name := range []string{state.state + "/runtime-lifecycle.lock", state.state + "/docker-jobs/compose.lock"} {
		st, err := os.Lstat(name)
		if err != nil || !moduleRecordInfo(st, false, false) || st.Size() != 0 {
			t.Fatal("existing exact QA lock required", name, err)
		}
		before[name] = st
	}
	mux := http.NewServeMux()
	New(Config{}).dockerRoutes(mux)
	request := func(budget time.Duration) (int, string) {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		r := httptest.NewRequest(http.MethodPost, "/v1/docker/containers/not-a-valid-object/restart", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if status, body := request(2 * time.Second); status != 400 {
		t.Fatal("actual guarded handler did not reach inert invalid-parameter check", status, body)
	}
	f, err := os.OpenFile(state.state+"/runtime-lifecycle.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("existing installer lease is busy; no reset or retry", err)
	}
	if status, body := request(100 * time.Millisecond); status != 409 {
		t.Fatal("installer EX lease did not block a new actual HTTP mutation", status, body)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if status, body := request(2 * time.Second); status != 400 {
		t.Fatal("settled installer lease remained blocked", status, body)
	}
	for name, st := range before {
		after, err := os.Lstat(name)
		if err != nil || !geoStoreStableInfo(st, after) {
			t.Fatal("actual lock inode, bytes or permissions changed", name, err)
		}
	}
}
