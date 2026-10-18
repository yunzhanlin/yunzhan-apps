//go:build linux

package executor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/upgradeguard"
)

var errDockerMutation = errors.New("Docker 原变更锁、升级状态或未结事务不能核对；未执行容器、镜像或配置变更")

// Production uses only these fixed paths/policies. The unexported filesystem
// seam is for actual trusted-root fixtures, never a request/config/CLI option.
type dockerMutationStore struct {
	state   string
	blocked func() bool
	pending func(context.Context) error
}

func productionDockerMutationStore() dockerMutationStore {
	return dockerMutationStore{
		state: "/var/lib/panel-executor", blocked: upgradeguard.Blocked,
		pending: (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade,
	}
}

type dockerMutationTree struct {
	roots []*os.Root
	paths []string
}

func (t *dockerMutationTree) close() {
	for i := len(t.roots) - 1; i >= 0; i-- {
		_ = t.roots[i].Close()
	}
}

func (t *dockerMutationTree) current() bool {
	for i, root := range t.roots {
		opened, e1 := root.Stat(".")
		visible, e2 := os.Lstat(t.paths[i])
		if e1 != nil || e2 != nil || !os.SameFile(opened, visible) || !moduleRecordInfo(opened, true, i != len(t.roots)-1) || !moduleRecordInfo(visible, true, i != len(t.roots)-1) {
			return false
		}
	}
	return true
}

func openDockerMutationTree(state string) (*dockerMutationTree, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(state) || filepath.Clean(state) != state || state == "/" {
		return nil, errDockerMutation
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, errDockerMutation
	}
	t := &dockerMutationTree{roots: []*os.Root{root}, paths: []string{"/"}}
	names := strings.Split(strings.TrimPrefix(filepath.Join(state, "docker-jobs"), "/"), "/")
	fail := func() (*dockerMutationTree, error) { t.close(); return nil, errDockerMutation }
	for i, name := range names {
		before, err := root.Lstat(name)
		if err != nil || !moduleRecordInfo(before, true, i != len(names)-1) {
			return fail()
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return fail()
		}
		t.roots = append(t.roots, child)
		t.paths = append(t.paths, filepath.Join(t.paths[len(t.paths)-1], name))
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(before, opened) {
			return fail()
		}
		root = child
	}
	if !t.current() {
		return fail()
	}
	return t, nil
}

type dockerMutationHeldFile struct {
	file *os.File
	root *os.Root
	name string
	info os.FileInfo
}

func (f dockerMutationHeldFile) current() bool {
	opened, e1 := f.file.Stat()
	visible, e2 := f.root.Lstat(f.name)
	return e1 == nil && e2 == nil && moduleRecordInfo(opened, false, false) && opened.Size() == 0 && geoStoreStableInfo(f.info, opened) && geoStoreStableInfo(opened, visible)
}

func dockerMutationFile(root *os.Root, name string, create bool) (dockerMutationHeldFile, error) {
	var empty dockerMutationHeldFile
	flags := os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags = os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	}
	f, err := root.OpenFile(name, flags, 0)
	if errors.Is(err, os.ErrNotExist) && create {
		f, err = root.OpenFile(name, flags|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			f, err = root.OpenFile(name, flags, 0)
		} else if err == nil {
			if e := f.Sync(); e != nil {
				f.Close()
				return empty, errDockerMutation
			}
			if e := ruleFeedStoreSync(root); e != nil {
				f.Close()
				return empty, errDockerMutation
			}
		}
	}
	if err != nil {
		return empty, errDockerMutation
	}
	info, err := f.Stat()
	visible, e2 := root.Lstat(name)
	if err != nil || e2 != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 || !geoStoreStableInfo(info, visible) {
		f.Close()
		return empty, errDockerMutation
	}
	return dockerMutationHeldFile{f, root, name, info}, nil
}

func dockerMutationFlock(ctx context.Context, f dockerMutationHeldFile, mode int) error {
	if ctx == nil {
		return errDockerMutation
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil || !f.current() {
			return errDockerMutation
		}
		err := unix.Flock(int(f.file.Fd()), mode|unix.LOCK_NB)
		if err == nil {
			if !f.current() {
				return errDockerMutation
			}
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return errDockerMutation
		}
		select {
		case <-ctx.Done():
			return errDockerMutation
		case <-tick.C:
		}
	}
}

// Lifetime capability only, NOT actor/signature/job authority. Hold shared
// program/runtime lease FIRST, then the SAME exclusive Compose/Docker lease.
// Neither a browser field nor an expired context can manufacture this object.
type dockerMutationLease struct {
	mu      sync.RWMutex
	tree    *dockerMutationTree
	files   []dockerMutationHeldFile
	blocked func() bool
	closed  bool
}

func (l *dockerMutationLease) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	for i := len(l.files) - 1; i >= 0; i-- {
		_ = l.files[i].file.Close()
	}
	if l.tree != nil {
		l.tree.close()
	}
}

func (l *dockerMutationLease) currentLocked() bool {
	if l == nil || l.closed || l.blocked == nil || l.blocked() || l.tree == nil || !l.tree.current() || len(l.files) != 2 {
		return false
	}
	for _, f := range l.files {
		if !f.current() {
			return false
		}
	}
	return true
}

func (l *dockerMutationLease) use(ctx context.Context, fn func(context.Context) error) error {
	if l == nil || ctx == nil || fn == nil {
		return errDockerMutation
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if ctx.Err() != nil || !l.currentLocked() {
		return errDockerMutation
	}
	return fn(context.WithValue(ctx, dockerMutationContextKey{}, l))
}

// This raw acquisition is private for the forthcoming independently verified
// original app worker. General HTTP/legacy Docker jobs MUST use begin below;
// a filesystem lease alone never authorizes bypassing an unfinished app job.
func (s dockerMutationStore) acquire(ctx context.Context) (*dockerMutationLease, error) {
	if ctx == nil || ctx.Err() != nil || s.blocked == nil || s.blocked() {
		return nil, errDockerMutation
	}
	t, err := openDockerMutationTree(s.state)
	if err != nil {
		return nil, err
	}
	l := &dockerMutationLease{tree: t, blocked: s.blocked}
	fail := func() (*dockerMutationLease, error) { l.Close(); return nil, errDockerMutation }
	// Second-last held directory is the exact state directory, not a reopened
	// path. Do not create/repair the installer's lifecycle lock.
	lifecycle, err := dockerMutationFile(t.roots[len(t.roots)-2], "runtime-lifecycle.lock", false)
	if err != nil {
		return fail()
	}
	l.files = append(l.files, lifecycle)
	if dockerMutationFlock(ctx, lifecycle, unix.LOCK_SH) != nil || !t.current() || s.blocked() {
		return fail()
	}
	docker, err := dockerMutationFile(t.roots[len(t.roots)-1], "compose.lock", true)
	if err != nil {
		return fail()
	}
	l.files = append(l.files, docker)
	if dockerMutationFlock(ctx, docker, unix.LOCK_EX) != nil || !l.currentLocked() {
		return fail()
	}
	return l, nil
}

func (s dockerMutationStore) begin(ctx context.Context) (*dockerMutationLease, error) {
	if s.pending == nil {
		return nil, errDockerMutation
	}
	l, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if s.pending(ctx) != nil || !l.currentLocked() {
		l.Close()
		return nil, errDockerMutation
	}
	return l, nil
}

type dockerMutationContextKey struct{}

func withDockerMutation(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil {
		return errDockerMutation
	}
	if l, ok := ctx.Value(dockerMutationContextKey{}).(*dockerMutationLease); ok {
		return l.use(ctx, fn)
	}
	acquire, cancel := context.WithTimeout(ctx, 3*time.Second)
	l, err := productionDockerMutationStore().begin(acquire)
	cancel()
	if err != nil {
		return err
	}
	defer l.Close()
	return l.use(ctx, fn)
}

func dockerMutationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The legacy job observer can reconcile its result file. It is not a
		// pure read and must use the same leases as mutations.
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !strings.HasPrefix(r.URL.Path, "/v1/docker/jobs/") {
			next.ServeHTTP(w, r)
			return
		}
		err := withDockerMutation(r.Context(), func(ctx context.Context) error { next.ServeHTTP(w, r.WithContext(ctx)); return nil })
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "3")
			respond(w, 409, map[string]string{"error": errDockerMutation.Error()})
		}
	})
}
