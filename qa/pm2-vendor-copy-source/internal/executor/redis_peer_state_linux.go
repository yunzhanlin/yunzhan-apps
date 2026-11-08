//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

var errRedisPeer = errors.New("Redis 管理对端的实例、进程或套接字身份不可验证；未发送管理凭据")

type redisServiceAccount struct{ UID, GID uint32 }

func redisServiceIdentity() (redisServiceAccount, error) {
	u, err := user.Lookup("panel-redis")
	if err != nil || u.Username != "panel-redis" {
		return redisServiceAccount{}, errRedisPeer
	}
	g, err := user.LookupGroup("panel-redis")
	if err != nil || g.Name != "panel-redis" || g.Gid != u.Gid {
		return redisServiceAccount{}, errRedisPeer
	}
	number := func(raw string) (uint32, bool) {
		n, err := strconv.ParseUint(raw, 10, 31)
		return uint32(n), err == nil && n > 0 && strconv.FormatUint(n, 10) == raw
	}
	uid, a := number(u.Uid)
	gid, b := number(u.Gid)
	if !a || !b {
		return redisServiceAccount{}, errRedisPeer
	}
	return redisServiceAccount{uid, gid}, nil
}

type redisPeerUnit struct {
	PID                         int
	Invocation, Cgroup, Started string
}

func redisPeerUnitState(raw, id string) (redisPeerUnit, error) {
	bad := func() (redisPeerUnit, error) { return redisPeerUnit{}, errRedisPeer }
	if !core.ValidID(id) || len(raw) > 8192 || !strings.HasSuffix(raw, "\n") {
		return bad()
	}
	required := map[string]bool{"LoadState": true, "ActiveState": true, "SubState": true, "MainPID": true,
		"InvocationID": true, "ControlGroup": true, "ExecMainStartTimestampMonotonic": true, "User": true, "Group": true}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !required[key] || strings.ContainsAny(value, "\x00\r") {
			return bad()
		}
		if _, duplicate := values[key]; duplicate {
			return bad()
		}
		values[key] = value
	}
	if len(values) != len(required) || values["LoadState"] != "loaded" || values["ActiveState"] != "active" ||
		values["SubState"] != "running" || values["User"] != "root" || values["Group"] != "panel-redis" ||
		!core.ValidID(values["InvocationID"]) {
		return bad()
	}
	pid, err := strconv.ParseUint(values["MainPID"], 10, 31)
	if err != nil || pid < 2 || strconv.FormatUint(pid, 10) != values["MainPID"] {
		return bad()
	}
	started, err := strconv.ParseUint(values["ExecMainStartTimestampMonotonic"], 10, 64)
	if err != nil || started == 0 || strconv.FormatUint(started, 10) != values["ExecMainStartTimestampMonotonic"] {
		return bad()
	}
	unit := redisUnit(id)
	group := values["ControlGroup"]
	if group != "/system.slice/"+unit && group != "/system.slice/system-panel\\x2dredis.slice/"+unit {
		return bad()
	}
	return redisPeerUnit{int(pid), values["InvocationID"], group, values["ExecMainStartTimestampMonotonic"]}, nil
}

// Select the actual systemd hierarchy independently. Other controllers are not
// borrowed as unit authority. This supports unified v2 and name=systemd v1,
// including a v1/hybrid host with an unused unified root controller.
func redisPeerCgroup(raw, expected string) bool {
	if len(raw) > 8192 || !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") > 64 {
		return false
	}
	seen := map[string]bool{}
	named, unified := "", ""
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] == "" || seen[fields[0]] {
			return false
		}
		seen[fields[0]] = true
		n, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != fields[0] || !filepath.IsAbs(fields[2]) ||
			filepath.Clean(fields[2]) != fields[2] || strings.ContainsAny(fields[2], "\x00\r\t ") {
			return false
		}
		if n == 0 {
			if fields[1] != "" || unified != "" {
				return false
			}
			unified = fields[2]
			continue
		}
		if fields[1] == "" {
			return false
		}
		controllers := strings.Split(fields[1], ",")
		local := map[string]bool{}
		for _, controller := range controllers {
			if controller == "" || local[controller] || strings.ContainsAny(controller, "\x00\r\t /") {
				return false
			}
			local[controller] = true
			if controller == "name=systemd" {
				if len(controllers) != 1 || named != "" {
					return false
				}
				named = fields[2]
			}
		}
	}
	if named != "" {
		return named == expected
	}
	return unified != "" && unified == expected
}

func redisPeerProcessStatus(raw string, account redisServiceAccount) bool {
	if account.UID == 0 || account.GID == 0 || !taskSafeProcessStatus(raw, account.UID) {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "Gid" && key != "Groups") {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		values := strings.Fields(value)
		want := 4
		if key == "Groups" {
			want = 1
		}
		if len(values) != want {
			return false
		}
		for _, v := range values {
			if v != strconv.FormatUint(uint64(account.GID), 10) {
				return false
			}
		}
	}
	return len(seen) == 2
}

type redisPeerIdentity struct {
	Unit                              redisPeerUnit
	Start                             uint64
	UID, GID                          uint32
	ProcessDevice, ProcessInode       uint64
	ExecutableDevice, ExecutableInode uint64
}

func redisPeerProcRead(directory *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRedisPeer
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errRedisPeer
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errRedisPeer
	}
	return raw, nil
}

func redisPeerProcessAt(ctx context.Context, procRoot, binary, config string, account redisServiceAccount, unit redisPeerUnit) (redisPeerIdentity, error) {
	var zero redisPeerIdentity
	if ctx.Err() != nil || unit.PID < 2 || account.UID == 0 || account.GID == 0 ||
		!filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot ||
		!filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return zero, errRedisPeer
	}
	if threatIDSTrustedParents(filepath.Dir(binary), false) != nil {
		return zero, errRedisPeer
	}
	executable, err := os.OpenFile(binary, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return zero, errRedisPeer
	}
	defer executable.Close()
	expected, err := executable.Stat()
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		expected.Mode().Perm()&0022 != 0 || expected.Mode().Perm()&0005 != 0005 || expected.Size() <= 0 || expected.Size() > 256<<20 {
		return zero, errRedisPeer
	}
	exeStat, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || exeStat.Uid != 0 || exeStat.Gid != 0 || exeStat.Nlink != 1 {
		return zero, errRedisPeer
	}
	procPath := filepath.Join(procRoot, strconv.Itoa(unit.PID))
	directory, err := os.OpenFile(procPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return zero, errRedisPeer
	}
	defer directory.Close()
	before, err := directory.Stat()
	if err != nil || !before.IsDir() {
		return zero, errRedisPeer
	}
	statRaw, err := redisPeerProcRead(directory, "stat", 8192)
	if err != nil || !strings.HasPrefix(string(statRaw), strconv.Itoa(unit.PID)+" (") {
		return zero, errRedisPeer
	}
	process, err := parseProcStat(unit.PID, string(statRaw), uint64(os.Getpagesize()))
	if err != nil || process.StartTime == 0 || process.State == "Z" || process.State == "X" || process.State == "x" {
		return zero, errRedisPeer
	}
	group, err := redisPeerProcRead(directory, "cgroup", 8192)
	if err != nil || !redisPeerCgroup(string(group), unit.Cgroup) {
		return zero, errRedisPeer
	}
	status, err := redisPeerProcRead(directory, "status", 16384)
	if err != nil || !redisPeerProcessStatus(string(status), account) {
		return zero, errRedisPeer
	}
	command, err := redisPeerProcRead(directory, "cmdline", 16384)
	if err != nil || !bytes.Equal(command, []byte(binary+"\x00"+config+"\x00")) {
		return zero, errRedisPeer
	}
	environment, err := redisPeerProcRead(directory, "environ", 4096)
	if err != nil || string(environment) != "PATH=/usr/bin:/bin\x00LANG=C\x00HOME=/nonexistent\x00" {
		return zero, errRedisPeer
	}
	// Only this kernel-owned proc-directory's literal magic link is followed.
	// No user-controlled link or pathname can select the executable reference.
	fd, err := unix.Openat(int(directory.Fd()), "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, errRedisPeer
	}
	actualFile := os.NewFile(uintptr(fd), "kernel-redis-executable")
	defer actualFile.Close()
	actual, err := actualFile.Stat()
	if err != nil || !os.SameFile(expected, actual) {
		return zero, errRedisPeer
	}
	again, err := redisPeerProcRead(directory, "stat", 8192)
	next, parseErr := parseProcStat(unit.PID, string(again), uint64(os.Getpagesize()))
	after, statErr := directory.Stat()
	named, pathErr := os.Lstat(procPath)
	finalExe, exeErr := executable.Stat()
	namedExe, nameErr := os.Lstat(binary)
	if err != nil || parseErr != nil || next.StartTime != process.StartTime || next.State == "Z" || next.State == "X" || next.State == "x" ||
		statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) ||
		exeErr != nil || nameErr != nil || !geoStoreStableInfo(expected, finalExe) || !geoStoreStableInfo(finalExe, namedExe) || ctx.Err() != nil {
		return zero, errRedisPeer
	}
	procStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return zero, errRedisPeer
	}
	return redisPeerIdentity{unit, process.StartTime, account.UID, account.GID, uint64(procStat.Dev), procStat.Ino, uint64(exeStat.Dev), exeStat.Ino}, nil
}

func redisManagementIdentity(ctx context.Context, instance core.RedisInstance, account redisServiceAccount) (redisPeerIdentity, error) {
	var empty redisPeerIdentity
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" || core.ValidateRedisInstance(instance) != nil || instance.AuthMode != core.RedisACLAuthMode {
		return empty, errRedisPeer
	}
	raw, err := RunCommand(ctx, "/usr/bin/systemctl", "show", redisUnit(instance.ID),
		"--property=LoadState,ActiveState,SubState,MainPID,InvocationID,ControlGroup,ExecMainStartTimestampMonotonic,User,Group")
	if err != nil {
		return empty, errRedisPeer
	}
	unit, err := redisPeerUnitState(raw, instance.ID)
	if err != nil {
		return empty, errRedisPeer
	}
	return redisPeerProcessAt(ctx, "/proc", release.Prefix()+"/bin/redis-server", filepath.Join(redisConfig(instance.ID), "redis.conf"), account, unit)
}
