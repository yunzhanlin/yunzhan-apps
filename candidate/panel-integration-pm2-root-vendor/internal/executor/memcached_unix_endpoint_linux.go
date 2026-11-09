//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

var errMemcachedUnix = errors.New("Memcached Unix Socket 的专用目录、账户、真实服务进程或协议回复不可核对；未确认成功")

type memcachedUnixAccount struct{ UID, GID uint32 }
type memcachedUnixGroup struct {
	Name, Gid string
	Members   []string
}

func memcachedUnixDecodeGroup(raw []byte, gid string) (*memcachedUnixGroup, error) {
	if len(raw) > 1<<20 || !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) {
		return nil, errMemcachedUnix
	}
	if _, e := memcachedUnixNumber(gid); e != nil {
		return nil, e
	}
	var result *memcachedUnixGroup
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 {
			return nil, errMemcachedUnix
		}
		if f[2] != gid {
			continue
		}
		if result != nil || f[0] == "" {
			return nil, errMemcachedUnix
		}
		members := []string{}
		if f[3] != "" {
			members = strings.Split(f[3], ",")
		}
		if len(members) > 16 {
			return nil, errMemcachedUnix
		}
		seen := map[string]bool{}
		for _, m := range members {
			if m == "" || seen[m] || strings.TrimSpace(m) != m {
				return nil, errMemcachedUnix
			}
			seen[m] = true
		}
		result = &memcachedUnixGroup{Name: f[0], Gid: gid, Members: members}
	}
	if result == nil {
		return nil, errMemcachedUnix
	}
	return result, nil
}

func memcachedUnixLookupGroup(gid string) (*memcachedUnixGroup, error) {
	f, e := os.OpenFile("/etc/group", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, errMemcachedUnix
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() > 1<<20 {
		return nil, errMemcachedUnix
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Nlink != 1 {
		return nil, errMemcachedUnix
	}
	raw, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return nil, errMemcachedUnix
	}
	after, e1 := f.Stat()
	named, e2 := os.Lstat("/etc/group")
	if e1 != nil || e2 != nil || !geoStoreStableInfo(before, after) || !geoStoreStableInfo(after, named) {
		return nil, errMemcachedUnix
	}
	return memcachedUnixDecodeGroup(raw, gid)
}

func memcachedUnixNumber(raw string) (uint32, error) {
	v, e := strconv.ParseUint(raw, 10, 31)
	if e != nil || v == 0 || strconv.FormatUint(v, 10) != raw {
		return 0, errMemcachedUnix
	}
	return uint32(v), nil
}

func memcachedUnixResolveAccount(site string, lookupUser func(string) (*user.User, error), lookupGroup func(string) (*memcachedUnixGroup, error)) (memcachedUnixAccount, error) {
	if site != "" && !core.ValidID(site) || lookupUser == nil || lookupGroup == nil {
		return memcachedUnixAccount{}, errMemcachedUnix
	}
	name, comment := "panel-memcached", "panel-memcached"
	if site != "" {
		name, comment = siteUser(site), "panel-managed-"+site
	}
	u, e := lookupUser(name)
	if e != nil || u == nil || u.Username != name || u.Name != comment || site == "" && u.HomeDir != "/nonexistent" {
		return memcachedUnixAccount{}, errMemcachedUnix
	}
	uid, e1 := memcachedUnixNumber(u.Uid)
	gid, e2 := memcachedUnixNumber(u.Gid)
	if e1 != nil || e2 != nil {
		return memcachedUnixAccount{}, errMemcachedUnix
	}
	g, e := lookupGroup(u.Gid)
	if e != nil || g == nil || g.Gid != u.Gid || g.Name != name {
		return memcachedUnixAccount{}, errMemcachedUnix
	}
	// Do not silently grant a shared supplementary group access to this cache.
	for _, member := range g.Members {
		if member != name {
			return memcachedUnixAccount{}, errMemcachedUnix
		}
	}
	return memcachedUnixAccount{uid, gid}, nil
}

func memcachedUnixPeerMatches(peer *unix.Ucred, pid int, account memcachedUnixAccount) bool {
	return peer != nil && pid > 1 && pid <= 0x7fffffff && account.UID > 0 && account.GID > 0 && account.UID <= 0x7fffffff && account.GID <= 0x7fffffff && peer.Pid == int32(pid) && peer.Uid == account.UID && peer.Gid == account.GID
}

func memcachedUnixSocketInfo(path string, account memcachedUnixAccount) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) >= 108 || filepath.Base(path) != "cache.sock" || account.UID == 0 || account.GID == 0 {
		return nil, errMemcachedUnix
	}
	parent, e := os.Lstat(filepath.Dir(path))
	if e != nil || !parent.IsDir() || parent.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || parent.Mode().Perm() != 0770 {
		return nil, errMemcachedUnix
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != account.GID {
		return nil, errMemcachedUnix
	}
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0666 {
		return nil, errMemcachedUnix
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != account.UID || s.Gid != account.GID || s.Nlink != 1 {
		return nil, errMemcachedUnix
	}
	// The socket mode permits the privileged controller to connect without
	// DAC_OVERRIDE. Authorization is the ROOT-owned, non-replaceable 0770
	// directory, its exact private site group (or Root-only admin ancestor),
	// and the live kernel peer PID/UID/GID. It is not a public filesystem socket.
	return info, nil
}

type memcachedUnixVerifiedConnection struct {
	*net.UnixConn
	directory *os.File
	pidfd     int
	cancel    context.CancelFunc
	bound     context.Context
	done      chan struct{}
	once      sync.Once
}

func (c *memcachedUnixVerifiedConnection) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		c.cancel()
		if c.UnixConn != nil {
			err = c.UnixConn.Close()
		}
		if c.pidfd >= 0 {
			unix.Close(c.pidfd)
		}
		if c.directory != nil {
			c.directory.Close()
		}
	})
	return err
}

// Returns a single verified, bounded connection BEFORE sending any protocol
// bytes. VERSION and cache operations must use this very connection; a prior
// readiness probe does not authorize an unverified second connection.
func dialMemcachedUnixVerifiedAt(ctx context.Context, path string, pid int, account memcachedUnixAccount) (*memcachedUnixVerifiedConnection, error) {
	if ctx == nil || ctx.Err() != nil || pid < 2 {
		return nil, errMemcachedUnix
	}
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	c := &memcachedUnixVerifiedConnection{pidfd: -1, cancel: cancel, bound: bound, done: make(chan struct{})}
	good := false
	defer func() {
		if !good {
			c.Close()
		}
	}()
	directory, dirInfo, e := openMemcachedUnixSocketDirectory(path, account)
	if e != nil {
		return nil, fmt.Errorf("%w: directory identity", e)
	}
	c.directory = directory
	before, e := memcachedUnixSocketAt(directory, account)
	if e != nil {
		return nil, fmt.Errorf("%w: socket identity", e)
	}
	identity, e := memcachedUnixProcessAt(pid, account)
	if e != nil {
		return nil, fmt.Errorf("%w: process identity", e)
	}
	c.pidfd, e = unix.PidfdOpen(pid, 0)
	if e != nil || !redisPeerPIDAlive(c.pidfd) {
		return nil, fmt.Errorf("%w: live pidfd", errMemcachedUnix)
	}
	rawConn, e := (&net.Dialer{}).DialContext(bound, "unix", fmt.Sprintf("/proc/self/fd/%d/cache.sock", directory.Fd()))
	if e != nil {
		return nil, fmt.Errorf("%w: socket connect: %w", errMemcachedUnix, e)
	}
	var ok bool
	c.UnixConn, ok = rawConn.(*net.UnixConn)
	if !ok {
		rawConn.Close()
		return nil, errMemcachedUnix
	}
	deadline, _ := bound.Deadline()
	if c.SetDeadline(deadline) != nil {
		return nil, errMemcachedUnix
	}
	go func() {
		select {
		case <-bound.Done():
			c.Close()
		case <-c.done:
		}
	}()
	raw, e := c.SyscallConn()
	if e != nil {
		return nil, errMemcachedUnix
	}
	var peer *unix.Ucred
	var peerErr error
	if raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || peerErr != nil || !memcachedUnixPeerMatches(peer, pid, account) {
		return nil, fmt.Errorf("%w: actual peer credentials", errMemcachedUnix)
	}
	after, e := memcachedUnixSocketAt(directory, account)
	current, procErr := memcachedUnixProcessAt(pid, account)
	visible, dirErr := os.Lstat(filepath.Dir(path))
	if e != nil {
		return nil, fmt.Errorf("%w: socket revalidation", e)
	}
	if !sameMemcachedUnixSocketObservation(before, after) {
		return nil, fmt.Errorf("%w: socket metadata changed [device=%t inode=%t mode=%t owner=%t links=%t access-time=%t modify-time=%t change-time=%t]", errMemcachedUnix, before.Dev == after.Dev, before.Ino == after.Ino, before.Mode == after.Mode, before.Uid == after.Uid && before.Gid == after.Gid, before.Nlink == after.Nlink, before.Atim == after.Atim, before.Mtim == after.Mtim, before.Ctim == after.Ctim)
	}
	if procErr != nil {
		return nil, fmt.Errorf("%w: process revalidation", procErr)
	}
	if current != identity {
		return nil, fmt.Errorf("%w: process generation changed [start=%t device=%t inode=%t]", errMemcachedUnix, current.Start == identity.Start, current.Device == identity.Device, current.Inode == identity.Inode)
	}
	if dirErr != nil || !os.SameFile(dirInfo, visible) || !memcachedUnixDirectoryInfo(visible, account) {
		return nil, fmt.Errorf("%w: directory continuity", errMemcachedUnix)
	}
	if !redisPeerPIDAlive(c.pidfd) {
		return nil, fmt.Errorf("%w: process no longer live", errMemcachedUnix)
	}
	if bound.Err() != nil {
		return nil, fmt.Errorf("%w: verification deadline", errMemcachedUnix)
	}
	good = true
	return c, nil
}

func memcachedUnixReadyAt(ctx context.Context, path string, pid int, account memcachedUnixAccount) error {
	conn, e := dialMemcachedUnixVerifiedAt(ctx, path, pid, account)
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = io.WriteString(conn, "version\r\n"); e != nil {
		return errMemcachedUnix
	}
	want := []byte("VERSION 1.6.45\r\n")
	reply := make([]byte, len(want))
	if _, e = io.ReadFull(conn, reply); e != nil || !slices.Equal(reply, want) || conn.bound.Err() != nil || !redisPeerPIDAlive(conn.pidfd) {
		return errMemcachedUnix
	}
	return nil
}
