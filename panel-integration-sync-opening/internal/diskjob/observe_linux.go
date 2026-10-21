//go:build linux

package diskjob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type NativeObservation struct {
	Process string
	Scope   string
}

// Read-only identity probe; never signal a numeric PID, restart a unit or
// infer scope success from MainPID (scope units have no main process).
func ObserveNative(in Request, d Dispatch, s Started) NativeObservation {
	out := NativeObservation{Process: "unknown", Scope: "unknown"}
	if ValidateStarted(s, d, in) != nil || os.Geteuid() != 0 {
		return out
	}
	out.Scope = observeScope(s.Policy.Cgroup)
	out.Process = observeProcess(s)
	return out
}

func bootID() (string, error) {
	raw, err := fixedKernelRead("/proc/sys/kernel/random/boot_id", 128, unix.PROC_SUPER_MAGIC)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !boot.MatchString(id) {
		return "", ErrReceipt
	}
	return id, nil
}

func processTicks(raw []byte, pid string) (string, error) {
	if len(raw) < 1 || len(raw) > 8192 || !bytes.HasPrefix(raw, []byte(pid+" (")) {
		return "", ErrReceipt
	}
	end := bytes.LastIndex(raw, []byte(") "))
	if end < len(pid)+2 {
		return "", ErrReceipt
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 || !CanonicalInteger(fields[19], true) {
		return "", ErrReceipt
	}
	return fields[19], nil
}

func pidExited(fd int) (bool, error) {
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(poll, 0); err != nil {
		return false, err
	}
	if poll[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
		return false, ErrReceipt
	}
	return poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
}

func processSHA(name string) (string, error) {
	// Only constructed from a previously validated decimal PID; kernel magic
	// link is deliberately followed while a pidfd pins this original process.
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 256<<20 {
		return "", ErrReceipt
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return "", ErrReceipt
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil || n != info.Size() {
		return "", ErrReceipt
	}
	after, err := f.Stat()
	if err != nil || info.Size() != after.Size() || info.ModTime() != after.ModTime() {
		return "", ErrReceipt
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func observeProcess(s Started) string {
	return probeOriginalProcess(s, false)
}

// No caller-controlled signal or numeric-PID kill. The signal goes through
// the SAME pidfd used for the complete original identity probe.
func SignalOriginal(in Request, d Dispatch, s Started) (bool, error) {
	if ValidateStarted(s, d, in) != nil || os.Geteuid() != 0 {
		return false, ErrReceipt
	}
	if observeScope(s.Policy.Cgroup) != "busy" {
		return false, ErrReceipt
	}
	switch probeOriginalProcess(s, true) {
	case "signaled":
		return true, nil
	case "gone":
		return false, nil
	default:
		return false, ErrReceipt
	}
}

func ObserveScope(id string) string {
	unit, err := UnitName(id, false)
	if err != nil || os.Geteuid() != 0 {
		return "unknown"
	}
	return observeScope("/system.slice/" + unit)
}

func probeOriginalProcess(s Started, terminate bool) string {
	pid, err := strconv.ParseUint(s.PID, 10, 31)
	if err != nil || pid < 2 || !CanonicalInteger(s.PID, true) || !CanonicalInteger(s.StartTicks, true) || ValidateHost(s.Policy.Host) != nil || !ValidSHA(s.ExecutorSHA) {
		return "unknown"
	}
	boot, err := bootID()
	if err != nil {
		return "unknown"
	}
	if boot != s.Policy.Host.BootID {
		return "gone"
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if errors.Is(err, unix.ESRCH) {
		return "gone"
	}
	if err != nil {
		return "unknown"
	}
	defer unix.Close(fd)
	ended := func() bool { gone, err := pidExited(fd); return err == nil && gone }
	if ended() {
		return "gone"
	}
	base := "/proc/" + s.PID
	raw, err := fixedKernelRead(base+"/stat", 8192, unix.PROC_SUPER_MAGIC)
	if err != nil {
		if ended() {
			return "gone"
		}
		return "unknown"
	}
	ticks, err := processTicks(raw, s.PID)
	if err != nil {
		return "unknown"
	}
	if ticks != s.StartTicks {
		return "gone"
	} // PID reused, not this original.
	ns, err := namespace(base + "/ns/mnt")
	if err != nil || strconv.FormatUint(uint64(ns.Dev), 10)+":"+strconv.FormatUint(ns.Ino, 10) != s.Policy.Host.NamespaceID {
		if ended() {
			return "gone"
		}
		return "unknown"
	}
	raw, err = fixedKernelRead(base+"/cgroup", 4096, unix.PROC_SUPER_MAGIC)
	if err != nil || strings.TrimSpace(string(raw)) != "0::"+s.Policy.Cgroup {
		if ended() {
			return "gone"
		}
		return "unknown"
	}
	sha, err := processSHA(base + "/exe")
	if err != nil || sha != s.ExecutorSHA {
		if ended() {
			return "gone"
		}
		return "unknown"
	}
	// A pidfd avoids adopting a recycled numeric PID across the slow hash.
	raw, err = fixedKernelRead(base+"/stat", 8192, unix.PROC_SUPER_MAGIC)
	after, tickErr := processTicks(raw, s.PID)
	if ended() {
		return "gone"
	}
	if err != nil || tickErr != nil || after != s.StartTicks {
		return "unknown"
	}
	if terminate {
		if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return "gone"
			}
			return "unknown"
		}
		return "signaled"
	}
	return "alive"
}

func cgroupFile(fd int, name string, limit int64) ([]byte, error) {
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(n), "fixed-cgroup-state")
	defer f.Close()
	var st unix.Statfs_t
	if unix.Fstatfs(n, &st) != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, ErrReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrReceipt
	}
	return raw, nil
}

func populated(raw []byte) (bool, error) {
	fields := strings.Fields(string(raw))
	seen := map[string]bool{}
	var busy bool
	if len(fields) < 2 || len(fields)%2 != 0 || len(fields) > 4 {
		return false, ErrReceipt
	}
	for i := 0; i < len(fields); i += 2 {
		k, v := fields[i], fields[i+1]
		if k != "populated" && k != "frozen" || seen[k] || v != "0" && v != "1" {
			return false, ErrReceipt
		}
		seen[k] = true
		if k == "populated" {
			busy = v == "1"
		}
	}
	if !seen["populated"] {
		return false, ErrReceipt
	}
	return busy, nil
}

func observeScope(group string) string {
	unit := strings.TrimPrefix(group, "/system.slice/")
	if group != "/system.slice/"+unit {
		return "unknown"
	}
	id := strings.TrimSuffix(strings.TrimPrefix(unit, "panel-disk-host-"), ".scope")
	if wanted, err := UnitName(id, false); err != nil || unit != wanted {
		return "unknown"
	}
	fd, err := unix.Open("/sys/fs/cgroup", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "unknown"
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return "unknown"
	}
	slice, err := unix.Openat(fd, "system.slice", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "unknown"
	}
	defer unix.Close(slice)
	leaf, err := unix.Openat(slice, unit, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return "empty"
	}
	if err != nil {
		return "unknown"
	}
	defer unix.Close(leaf)
	before, err := cgroupFile(leaf, "cgroup.events", 1024)
	busy, e := populated(before)
	if err != nil || e != nil {
		return "unknown"
	}
	if busy {
		return "busy"
	}
	procs, err := cgroupFile(leaf, "cgroup.procs", 16384)
	if err != nil || len(bytes.TrimSpace(procs)) != 0 {
		return "unknown"
	}
	after, err := cgroupFile(leaf, "cgroup.events", 1024)
	busy, e = populated(after)
	if err != nil || e != nil {
		return "unknown"
	}
	if busy {
		return "busy"
	}
	var held, named unix.Stat_t
	if unix.Fstat(leaf, &held) != nil || unix.Fstatat(slice, unit, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != named.Dev || held.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "unknown"
	}
	return "empty"
}
