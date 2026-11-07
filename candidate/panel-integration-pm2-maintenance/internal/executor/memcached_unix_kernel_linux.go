//go:build linux

package executor

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

func memcachedUnixReadFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errMemcachedUnix
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errMemcachedUnix
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errMemcachedUnix
	}
	return raw, nil
}

func memcachedUnixHostAvailable() error {
	var fs unix.Statfs_t
	raw, err := memcachedUnixReadFile("/sys/fs/cgroup/cgroup.controllers", 4096)
	if err != nil || unix.Statfs("/sys/fs/cgroup", &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("此 Memcached 隔离版本需要可核对的 cgroup v2；未启动容器")
	}
	controllers := strings.Fields(string(raw))
	for _, name := range []string{"memory", "pids", "cpu"} {
		if !slices.Contains(controllers, name) {
			return errors.New("主机缺少 Memcached 所需的内存、进程或 CPU 控制器；未启动容器")
		}
	}
	return nil
}

func memcachedUnixKernel(ctx context.Context, pid int, id string, account memcachedUnixAccount, read func(string, int64) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || account.UID == 0 || account.GID == 0 || pid < 2 || len(id) != 64 || !dockerObjectPattern.MatchString(id) || read == nil {
		return errMemcachedUnix
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, e := read(filepath.Join(base, "stat"), 8192)
	before, parseErr := parseProcStat(pid, string(stat), uint64(os.Getpagesize()))
	if e != nil || parseErr != nil || !strings.HasPrefix(string(stat), strconv.Itoa(pid)+" (") || before.StartTime == 0 || before.State == "Z" || before.State == "X" || before.State == "x" {
		return errMemcachedUnix
	}
	cgroup, e := read(filepath.Join(base, "cgroup"), 8192)
	group := strings.TrimSuffix(strings.TrimPrefix(string(cgroup), "0::"), "\n")
	if e != nil || (string(cgroup) != "0::/system.slice/docker-"+id+".scope\n" && string(cgroup) != "0::/docker/"+id+"\n") {
		return errMemcachedUnix
	}
	status, e := read(filepath.Join(base, "status"), 16384)
	if e != nil || !memcachedUnixProcessStatus(string(status), account) || ctx.Err() != nil {
		return errMemcachedUnix
	}
	for name, want := range map[string]string{"memory.max": "201326592", "memory.swap.max": "0", "pids.max": "32"} {
		value, err := read(filepath.Join("/sys/fs/cgroup", group, name), 64)
		if err != nil || string(value) != want+"\n" {
			return errMemcachedUnix
		}
	}
	cpu, e := read(filepath.Join("/sys/fs/cgroup", group, "cpu.max"), 64)
	fields := strings.Fields(string(cpu))
	if e != nil || len(fields) != 2 {
		return errMemcachedUnix
	}
	quota, e1 := strconv.ParseUint(fields[0], 10, 64)
	period, e2 := strconv.ParseUint(fields[1], 10, 64)
	if e1 != nil || e2 != nil || quota != period || period < 1000 || period > 1_000_000 {
		return errMemcachedUnix
	}
	limits, e := read(filepath.Join(base, "limits"), 8192)
	matched := 0
	for _, line := range strings.Split(string(limits), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			// Pinned upstream1.6.45 main() sets BOTH RLIMIT_NOFILE values
			// to maxconns (-c256) before serving. Docker's independently
			// checked configured ceiling remains1024; accepting that desired
			// value as the process's actual value would hide failed admission.
			// github.com/memcached/memcached/blob/1.6.45/memcached.c#L5553
			if !slices.Equal(strings.Fields(line), []string{"Max", "open", "files", "256", "256", "files"}) {
				return errMemcachedUnix
			}
			matched++
		}
	}
	if e != nil || matched != 1 {
		return errMemcachedUnix
	}
	mounts, e := read(filepath.Join(base, "mountinfo"), 256<<10)
	matched = 0
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) > 9 && f[4] == "/" {
			options := strings.Split(f[5], ",")
			if !slices.Contains(options, "ro") || slices.Contains(options, "rw") {
				return errMemcachedUnix
			}
			matched++
		}
	}
	if e != nil || matched != 1 {
		return errMemcachedUnix
	}
	final, e := read(filepath.Join(base, "stat"), 8192)
	after, parseErr := parseProcStat(pid, string(final), uint64(os.Getpagesize()))
	groupAfter, groupErr := read(filepath.Join(base, "cgroup"), 8192)
	if ctx.Err() != nil || e != nil || parseErr != nil || !strings.HasPrefix(string(final), strconv.Itoa(pid)+" (") || after.StartTime != before.StartTime || after.State == "Z" || after.State == "X" || after.State == "x" || groupErr != nil || string(groupAfter) != string(cgroup) {
		return errMemcachedUnix
	}
	return nil
}
