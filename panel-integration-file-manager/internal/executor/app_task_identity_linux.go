//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type taskProcessIdentity struct {
	PID       int
	StartTime uint64
	UID       uint32
	Device    uint64
	Inode     uint64
	Unit      string
	Cgroup    string
	SafeUser  bool
}

// Never authorize a name fragment, a user/delegated hierarchy, a sub-cgroup,
// a deleted group or an arbitrary template instance. Both the normal automatic
// per-template slice and an explicit system.slice placement are supported.
func taskManagedCgroup(raw string) (string, string, bool) {
	if len(raw) > 8192 || !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") != 1 || !strings.HasPrefix(raw, "0::/") {
		return "", "", false
	}
	group := strings.TrimSuffix(strings.TrimPrefix(raw, "0::"), "\n")
	if len(group) > 4096 || strings.ContainsAny(group, "\x00\r\t ") || filepath.Clean(group) != group {
		return "", "", false
	}
	unit := filepath.Base(group)
	kind, instance, ok := strings.Cut(strings.TrimSuffix(unit, ".service"), "@")
	if !ok || !strings.HasSuffix(unit, ".service") {
		return "", "", false
	}
	valid := kind == "panel-node" && core.ValidID(instance) || kind == "panel-pm2" && moduleResourceID.MatchString(instance) || kind == "panel-php" && phpServiceID.MatchString(instance)
	if !valid || (group != "/system.slice/"+unit && group != "/system.slice/system-"+strings.ReplaceAll(kind, "-", `\x2d`)+".slice/"+unit) {
		return "", "", false
	}
	return unit, group, true
}

// proc directory ownership alone is insufficient: also reject saved/root UIDs,
// retained active capabilities, missing fields and disabled NoNewPrivileges.
// The capability bounding set is intentionally not treated as active authority.
func taskSafeProcessStatus(raw string, owner uint32) bool {
	if len(raw) > 16384 || owner == 0 {
		return false
	}
	wanted := map[string]bool{"Uid": true, "NoNewPrivs": true, "CapInh": true, "CapPrm": true, "CapEff": true, "CapAmb": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !wanted[key] {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		fields := strings.Fields(value)
		switch key {
		case "Uid":
			if len(fields) != 4 {
				return false
			}
			for _, field := range fields {
				n, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(n) != owner || strconv.FormatUint(n, 10) != field {
					return false
				}
			}
		case "NoNewPrivs":
			if len(fields) != 1 || fields[0] != "1" {
				return false
			}
		default:
			if len(fields) != 1 || len(fields[0]) != 16 || fields[0] != "0000000000000000" {
				return false
			}
		}
	}
	return len(seen) == len(wanted)
}

func readTaskProcessIdentity(procRoot string, pid int) (taskProcessIdentity, error) {
	var identity taskProcessIdentity
	bad := errors.New("进程的启动身份、账户或受管 cgroup 不可完整核对")
	if pid < 2 {
		return identity, bad
	}
	directory, err := os.OpenFile(filepath.Join(procRoot, strconv.Itoa(pid)), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return identity, bad
	}
	defer directory.Close()
	before, err := directory.Stat()
	if err != nil || !before.IsDir() {
		return identity, bad
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return identity, bad
	}
	read := func(name string, limit int64) (string, error) {
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", bad
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return "", bad
		}
		body, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(body)) > limit {
			return "", bad
		}
		return string(body), nil
	}
	stat, err := read("stat", 8192)
	if err != nil || !strings.HasPrefix(stat, strconv.Itoa(pid)+" (") {
		return identity, bad
	}
	process, err := parseProcStat(pid, stat, uint64(os.Getpagesize()))
	if err != nil || process.StartTime == 0 || process.State == "Z" || process.State == "X" || process.State == "x" {
		return identity, bad
	}
	cgroup, err := read("cgroup", 8192)
	unit, group, managed := taskManagedCgroup(cgroup)
	if err != nil || !managed {
		return identity, bad
	}
	status, err := read("status", 16384)
	if err != nil {
		return identity, bad
	}
	finalStat, err := read("stat", 8192)
	finalProcess, parseErr := parseProcStat(pid, finalStat, uint64(os.Getpagesize()))
	after, statErr := directory.Stat()
	if err != nil || parseErr != nil || !strings.HasPrefix(finalStat, strconv.Itoa(pid)+" (") || finalProcess.StartTime != process.StartTime || finalProcess.State == "Z" || finalProcess.State == "X" || finalProcess.State == "x" || statErr != nil || !os.SameFile(before, after) {
		return identity, bad
	}
	freshOwner, ok := after.Sys().(*syscall.Stat_t)
	if !ok || freshOwner.Uid != owner.Uid {
		return identity, bad
	}
	return taskProcessIdentity{PID: pid, StartTime: process.StartTime, UID: owner.Uid, Device: uint64(owner.Dev), Inode: owner.Ino, Unit: unit, Cgroup: group, SafeUser: taskSafeProcessStatus(status, owner.Uid)}, nil
}

func terminateTaskProcess(ctx context.Context, pid int, start uint64) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := readTaskProcessIdentity("/proc", pid)
	if err != nil || start == 0 || before.StartTime != start || !before.SafeUser {
		return nil, errors.New("仅允许终止身份、非 root 账户、无活动权限及受管 cgroup 均已核对的云栈进程")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	after, err := readTaskProcessIdentity("/proc", pid)
	if err != nil || after != before {
		return nil, errors.New("信号发送前进程授权或启动身份已经改变，未终止")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		return nil, err
	}
	// Signal delivery is not proof of exit; applications may handle SIGTERM and
	// supervisors may restart them. No automatic retry, SIGKILL or tree signal.
	return map[string]any{"signal": "SIGTERM", "pid": pid, "signal_accepted": true, "exit_verified": false}, nil
}
