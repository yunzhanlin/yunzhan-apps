//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var errRedisPrivilege = errors.New("Redis 专用启动器未完成固定账户降权、能力清除或 NoNewPrivileges 校验；未启动数据库")

// Private fault-model seam, not an RPC/profile/environment option. Production
// always uses the kernel operations below and the already resolved fixed NSS
// account. No caller can submit a UID, capability, command or executable path.
type redisPrivilegeOps struct {
	root         func() bool
	noNewPrivs   func() (int, error)
	groups       func([]int) error
	gid          func(int) error
	uid          func(int) error
	clearAmbient func() error
	clearCaps    func() error
	verify       func(uint32, uint32) error
}

func redisDropPrivilegesAt(uid, gid int, ops redisPrivilegeOps) error {
	if uid <= 0 || gid <= 0 || uint64(uid) > 0x7fffffff || uint64(gid) > 0x7fffffff ||
		ops.root == nil || ops.noNewPrivs == nil || ops.groups == nil || ops.gid == nil || ops.uid == nil ||
		ops.clearAmbient == nil || ops.clearCaps == nil || ops.verify == nil || !ops.root() {
		return errRedisPrivilege
	}
	nnp, err := ops.noNewPrivs()
	if err != nil || nnp != 1 {
		return errRedisPrivilege
	}
	for _, step := range []func() error{
		func() error { return ops.groups([]int{gid}) },
		func() error { return ops.gid(gid) },
		func() error { return ops.uid(uid) },
		ops.clearAmbient, ops.clearCaps,
		func() error { return ops.verify(uint32(uid), uint32(gid)) },
	} {
		if step() != nil {
			return errRedisPrivilege
		}
	}
	return nil
}

func redisVerifyDroppedIdentity(uid, gid uint32) error {
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	groups, err := os.Getgroups()
	if uid == 0 || gid == 0 || ruid != int(uid) || euid != int(uid) || suid != int(uid) ||
		rgid != int(gid) || egid != int(gid) || sgid != int(gid) || err != nil ||
		len(groups) != 1 || groups[0] != int(gid) {
		return errRedisPrivilege
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if unix.Capget(&header, &caps[0]) != nil || caps != [2]unix.CapUserData{} {
		return errRedisPrivilege
	}
	// Kernel-generated status for THIS locked thread, not an unrelated leader
	// or a goroutine that may move to another thread before exec.
	file, err := os.Open("/proc/thread-self/status")
	if err != nil {
		return errRedisPrivilege
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 || !taskSafeProcessStatus(string(raw), uid) {
		return errRedisPrivilege
	}
	return nil
}

func redisExecUnprivileged(binary, configuration string, uid, gid int) error {
	// Capability changes are per kernel thread. Keep the same thread from the
	// credential transition through capset/verification and exec. The other Go
	// threads are replaced by exec, never used to run an app with inherited caps.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ops := redisPrivilegeOps{
		root: func() bool { return os.Geteuid() == 0 },
		noNewPrivs: func() (int, error) {
			return unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		},
		groups: syscall.Setgroups, gid: syscall.Setgid, uid: syscall.Setuid,
		clearAmbient: func() error {
			return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
		},
		clearCaps: func() error {
			header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			caps := [2]unix.CapUserData{}
			return unix.Capset(&header, &caps[0])
		},
		verify: redisVerifyDroppedIdentity,
	}
	if err := redisDropPrivilegesAt(uid, gid, ops); err != nil {
		return err
	}
	// Both paths are resolved only by ServeRedis's fixed catalog, trusted
	// runtime ledger and instance authentication checks. No generic exec API.
	return syscall.Exec(binary, []string{binary, configuration},
		[]string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"})
}
