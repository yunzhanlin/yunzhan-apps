//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func redisRunDirectory(id string) string { return "/run/panel-redis-" + id }

func redisRuntimeDirectoryInfo(info os.FileInfo, account redisServiceAccount) bool {
	if info == nil || account.GID == 0 || !info.IsDir() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm() != 0770 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == account.GID
}

func openRedisRuntimeDirectory(dir string, account redisServiceAccount, empty bool) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		threatIDSTrustedParents(filepath.Dir(dir), false) != nil {
		return nil, nil, errRedisPeer
	}
	before, err := os.Lstat(dir)
	if err != nil || !redisRuntimeDirectoryInfo(before, account) {
		return nil, nil, errRedisPeer
	}
	fd, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, errRedisPeer
	}
	good := false
	defer func() {
		if !good {
			fd.Close()
		}
	}()
	opened, err := fd.Stat()
	if err != nil || !os.SameFile(before, opened) || !redisRuntimeDirectoryInfo(opened, account) {
		return nil, nil, errRedisPeer
	}
	entries, err := fd.ReadDir(3)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 2 || empty && len(entries) != 0 {
		return nil, nil, errRedisPeer
	}
	for _, entry := range entries {
		if entry.Name() != "admin.sock" && entry.Name() != "redis.pid" {
			return nil, nil, errRedisPeer
		}
		if entry.Name() == "redis.pid" {
			info, err := entry.Info()
			meta, ok := func() (*syscall.Stat_t, bool) {
				if info == nil {
					return nil, false
				}
				v, ok := info.Sys().(*syscall.Stat_t)
				return v, ok
			}()
			if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
				info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
				meta.Uid != account.UID || meta.Gid != account.GID || meta.Nlink != 1 || info.Size() <= 0 || info.Size() > 32 {
				return nil, nil, errRedisPeer
			}
		}
	}
	good = true
	return fd, before, nil
}

func redisManagementSocketInfo(directory *os.File, account redisServiceAccount) (os.FileInfo, error) {
	if account.UID == 0 || account.GID == 0 {
		return nil, errRedisPeer
	}
	var stat unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), "admin.sock", &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&07777 != 0666 ||
		stat.Uid != account.UID || stat.Gid != account.GID || stat.Nlink != 1 {
		return nil, errRedisPeer
	}
	// A descriptor-anchored kernel path cannot be redirected by renaming an
	// ancestor after validation. The fixed leaf is never a caller argument.
	info, err := os.Lstat(fmt.Sprintf("/proc/self/fd/%d/admin.sock", directory.Fd()))
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0666 {
		return nil, errRedisPeer
	}
	return info, nil
}

func redisPeerPIDAlive(fd int) bool {
	values := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(values, 0)
	return err == nil && n == 0 && values[0].Revents == 0
}

// This primitive never sends a protocol byte. Production supplies a fixed
// systemd/proc observation closure; it is not an HTTP/RPC option or test flag.
func dialRedisVerifiedAt(ctx context.Context, dir string, account redisServiceAccount,
	observe func(context.Context) (redisPeerIdentity, error)) (*net.UnixConn, *os.File, int, error) {
	if ctx.Err() != nil || observe == nil || account.UID == 0 || account.GID == 0 {
		return nil, nil, -1, errRedisPeer
	}
	directory, dirInfo, err := openRedisRuntimeDirectory(dir, account, false)
	if err != nil {
		return nil, nil, -1, errRedisPeer
	}
	committed := false
	pidfd := -1
	var conn *net.UnixConn
	defer func() {
		if !committed {
			if conn != nil {
				conn.Close()
			}
			if pidfd >= 0 {
				unix.Close(pidfd)
			}
			directory.Close()
		}
	}()
	before, err := observe(ctx)
	if err != nil || before.Unit.PID < 2 || before.Start == 0 || before.UID != account.UID || before.GID != account.GID {
		return nil, nil, -1, errRedisPeer
	}
	pidfd, err = unix.PidfdOpen(before.Unit.PID, 0)
	if err != nil || !redisPeerPIDAlive(pidfd) {
		return nil, nil, -1, errRedisPeer
	}
	socketBefore, err := redisManagementSocketInfo(directory, account)
	if err != nil {
		return nil, nil, -1, errRedisPeer
	}
	path := fmt.Sprintf("/proc/self/fd/%d/admin.sock", directory.Fd())
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, -1, errRedisPeer
	}
	var ok bool
	conn, ok = raw.(*net.UnixConn)
	if !ok {
		raw.Close()
		return nil, nil, -1, errRedisPeer
	}
	var credential *unix.Ucred
	var credentialErr error
	handle, err := conn.SyscallConn()
	if err != nil {
		return nil, nil, -1, errRedisPeer
	}
	if err = handle.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil ||
		credentialErr != nil || credential == nil || int(credential.Pid) != before.Unit.PID ||
		credential.Uid != account.UID || credential.Gid != account.GID {
		return nil, nil, -1, errRedisPeer
	}
	after, err := observe(ctx)
	socketAfter, socketErr := redisManagementSocketInfo(directory, account)
	current, dirErr := os.Lstat(dir)
	if err != nil || after != before || socketErr != nil || !geoStoreStableInfo(socketBefore, socketAfter) ||
		dirErr != nil || !os.SameFile(dirInfo, current) || !redisRuntimeDirectoryInfo(current, account) ||
		!redisPeerPIDAlive(pidfd) || ctx.Err() != nil {
		return nil, nil, -1, errRedisPeer
	}
	// Re-check the closed census without changing any pre-existing object.
	verify, info, err := openRedisRuntimeDirectory(dir, account, false)
	if err != nil {
		return nil, nil, -1, errRedisPeer
	}
	verify.Close()
	if !os.SameFile(dirInfo, info) {
		return nil, nil, -1, errRedisPeer
	}
	committed = true
	return conn, directory, pidfd, nil
}

type redisManagedConnection struct {
	*net.UnixConn
	directory, lease *os.File
	pidfd            int
	once             sync.Once
	closeErr         error
}

func (c *redisManagedConnection) Close() error {
	c.once.Do(func() {
		c.closeErr = c.UnixConn.Close()
		c.directory.Close()
		unix.Close(c.pidfd)
		c.lease.Close()
	})
	return c.closeErr
}

func redisManagementLease() (*os.File, error) {
	const path = "/var/lib/panel-executor/runtime-lifecycle.lock"
	if threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, errRedisPeer
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRedisPeer
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errRedisPeer
	}
	stat, good := info.Sys().(*syscall.Stat_t)
	if !good || stat.Uid != 0 || stat.Nlink != 1 || unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return nil, errRedisPeer
	}
	named, err := os.Lstat(path)
	if err != nil || !geoStoreStableInfo(info, named) {
		return nil, errRedisPeer
	}
	ok = true
	return f, nil
}

func dialRedisManagement(ctx context.Context, instance core.RedisInstance) (net.Conn, error) {
	if ctx.Err() != nil || core.ValidateRedisInstance(instance) != nil || instance.AuthMode != core.RedisACLAuthMode {
		return nil, errRedisPeer
	}
	account, err := redisServiceIdentity()
	if err != nil {
		return nil, errRedisPeer
	}
	lease, err := redisManagementLease()
	if err != nil {
		return nil, errRedisPeer
	}
	observe := func(ctx context.Context) (redisPeerIdentity, error) {
		return redisManagementIdentity(ctx, instance, account)
	}
	conn, directory, pidfd, err := dialRedisVerifiedAt(ctx, redisRunDirectory(instance.ID), account, observe)
	if err != nil {
		lease.Close()
		return nil, errRedisPeer
	}
	return &redisManagedConnection{UnixConn: conn, directory: directory, lease: lease, pidfd: pidfd}, nil
}

func validateRedisNewRuntimeDirectory(id string, gid uint32) error {
	if !core.ValidID(id) || gid == 0 {
		return errRedisPeer
	}
	// PID1, configured with User=root/Group=panel-redis/Mode0770, owns the
	// directory. Never chown/chmod an unsafe or nonempty existing directory.
	directory, _, err := openRedisRuntimeDirectory(redisRunDirectory(id), redisServiceAccount{GID: gid}, true)
	if err == nil {
		err = directory.Close()
	}
	return err
}
