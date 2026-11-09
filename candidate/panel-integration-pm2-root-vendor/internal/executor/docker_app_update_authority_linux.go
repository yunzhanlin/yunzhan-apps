//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

var errMemcachedCoreAuthority = errors.New("Memcached 原账户授权、保留请求或受信数据库无法核对；未执行容器变更")

// This SELECT-only reader is ONE condition of native admission, not a signing
// verifier, run lease, project inspection or capability to execute Docker. A
// worker must ALSO verify the compiled-key envelope and original live project,
// and recheck this current authority before effects AND after a slow pull.
// No route/CLI/config can supply a database path, UID or authority callback.
type memcachedUpdateCoreAuthority struct {
	mu      sync.Mutex
	base    string
	owner   uint32
	roots   []*os.Root
	paths   []string
	infos   []os.FileInfo
	file    *os.File
	info    os.FileInfo
	sides   map[string]os.FileInfo
	db      *sql.DB
	blocked func() bool
}

func openMemcachedUpdateCoreAuthority(ctx context.Context) (*memcachedUpdateCoreAuthority, error) {
	account, err := user.Lookup("panel")
	if err != nil {
		return nil, errMemcachedCoreAuthority
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return nil, errMemcachedCoreAuthority
	}
	return openMemcachedUpdateCoreAuthorityAt(ctx, "/var/lib/panel", uint32(uid))
}

func memcachedCoreInfo(info os.FileInfo, owner uint32, directory bool) bool {
	if info == nil || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != owner {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm()&0022 == 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0027 == 0 && s.Nlink == 1
}

func memcachedCoreSame(a, b os.FileInfo, owner uint32, directory bool) bool {
	if !memcachedCoreInfo(a, owner, directory) || !memcachedCoreInfo(b, owner, directory) || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	return a.Sys().(*syscall.Stat_t).Gid == b.Sys().(*syscall.Stat_t).Gid
}

// The explicit base/owner seam is only for real trusted-root filesystem and
// SQLite fixtures. Production above uses only the fixed Core path/account.
// Named descriptors are held; immutable=1 is NEVER used because ignoring live
// WAL could revive a revoked grant. No missing DB/parent/WAL file is created.
func openMemcachedUpdateCoreAuthorityAt(ctx context.Context, base string, owner uint32) (*memcachedUpdateCoreAuthority, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || !filepath.IsAbs(base) || filepath.Clean(base) != base || base == "/" {
		return nil, errMemcachedCoreAuthority
	}
	r := &memcachedUpdateCoreAuthority{base: base, owner: owner, blocked: upgradeguard.Blocked}
	fail := func() (*memcachedUpdateCoreAuthority, error) { r.Close(); return nil, errMemcachedCoreAuthority }
	root, err := os.OpenRoot("/")
	if err != nil {
		return fail()
	}
	r.roots, r.paths = []*os.Root{root}, []string{"/"}
	info, err := root.Stat(".")
	if err != nil || !memcachedCoreInfo(info, 0, true) {
		return fail()
	}
	r.infos = []os.FileInfo{info}
	names := strings.Split(strings.TrimPrefix(base, "/"), "/")
	for i, name := range names {
		uid := uint32(0)
		if i == len(names)-1 {
			uid = owner
		}
		before, err := root.Lstat(name)
		if err != nil || !memcachedCoreInfo(before, uid, true) {
			return fail()
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return fail()
		}
		r.roots = append(r.roots, child)
		r.paths = append(r.paths, filepath.Join(r.paths[len(r.paths)-1], name))
		opened, err := child.Stat(".")
		r.infos = append(r.infos, opened)
		if err != nil || !memcachedCoreSame(before, opened, uid, true) {
			return fail()
		}
		root = child
	}
	r.info, err = root.Lstat("panel.db")
	if err != nil || !memcachedCoreInfo(r.info, owner, false) || r.info.Size() < 4096 {
		return fail()
	}
	r.file, err = root.OpenFile("panel.db", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail()
	}
	opened, err := r.file.Stat()
	if err != nil || !memcachedCoreSame(r.info, opened, owner, false) {
		return fail()
	}
	var header [20]byte
	if n, err := r.file.ReadAt(header[:], 0); err != nil || n != len(header) || string(header[:16]) != "SQLite format 3\x00" || header[18] != header[19] || header[18] != 1 && header[18] != 2 {
		return fail()
	}
	r.sides = map[string]os.FileInfo{}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := root.Lstat("panel.db" + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || suffix == "-journal" || !memcachedCoreInfo(info, owner, false) {
			return fail()
		}
		r.sides[suffix] = info
	}
	if header[18] == 2 && (r.sides["-wal"] == nil || r.sides["-shm"] == nil) || header[18] == 1 && len(r.sides) != 0 || !r.current() {
		return fail()
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(base, "panel.db"), RawQuery: "mode=ro&_pragma=busy_timeout(1000)&_pragma=query_only(1)"}
	r.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return fail()
	}
	r.db.SetMaxOpenConns(1)
	r.db.SetMaxIdleConns(1)
	var queryOnly int
	if r.db.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly) != nil || queryOnly != 1 || !r.current() {
		return fail()
	}
	return r, nil
}

func (r *memcachedUpdateCoreAuthority) current() bool {
	if r == nil || r.file == nil || len(r.roots) < 2 {
		return false
	}
	for i, root := range r.roots {
		owner := uint32(0)
		if i == len(r.roots)-1 {
			owner = r.owner
		}
		opened, e1 := root.Stat(".")
		visible, e2 := os.Lstat(r.paths[i])
		if e1 != nil || e2 != nil || !memcachedCoreSame(r.infos[i], opened, owner, true) || !memcachedCoreSame(r.infos[i], visible, owner, true) {
			return false
		}
	}
	root := r.roots[len(r.roots)-1]
	opened, e1 := r.file.Stat()
	visible, e2 := root.Lstat("panel.db")
	if e1 != nil || e2 != nil || !memcachedCoreSame(r.info, opened, r.owner, false) || !memcachedCoreSame(r.info, visible, r.owner, false) {
		return false
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := root.Lstat("panel.db" + suffix)
		before := r.sides[suffix]
		if before == nil {
			if !errors.Is(err, os.ErrNotExist) {
				return false
			}
		} else if err != nil || !memcachedCoreSame(before, info, r.owner, false) {
			return false
		}
	}
	return true
}

func (r *memcachedUpdateCoreAuthority) check(ctx context.Context, seed core.MemcachedUpdateRecord) error {
	return r.original(ctx, seed, true)
}

func (r *memcachedUpdateCoreAuthority) restoration(ctx context.Context, seed core.MemcachedUpdateRecord) error {
	return r.original(ctx, seed, false)
}

func (r *memcachedUpdateCoreAuthority) original(ctx context.Context, seed core.MemcachedUpdateRecord, currentGrant bool) error {
	if r == nil {
		return errMemcachedCoreAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.db == nil || r.blocked == nil || r.blocked() || !r.current() {
		return errMemcachedCoreAuthority
	}
	store := &core.Store{DB: r.db}
	var err error
	if currentGrant {
		err = store.CheckMemcachedUpdateMutation(ctx, seed)
	} else {
		err = store.CheckMemcachedUpdateRestoration(ctx, seed)
	}
	if err != nil || !r.current() || r.blocked() || ctx.Err() != nil {
		return errMemcachedCoreAuthority
	}
	return nil
}

func (r *memcachedUpdateCoreAuthority) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		_ = r.db.Close()
		r.db = nil
	}
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	for i := len(r.roots) - 1; i >= 0; i-- {
		_ = r.roots[i].Close()
	}
	r.roots = nil
}
