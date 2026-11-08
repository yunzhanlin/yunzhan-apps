//go:build linux

package diskjob

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/diskusage"
)

var ErrHostView = errors.New("全盘入口未固定在PID1宿主视图；未将隔离/替代目录称为全盘")
var ErrWorkerPolicy = errors.New("扫描进程的权限、资源或控制组约束无法核对；未降级执行")

func fixedKernelRead(name string, limit int64, magic int64) ([]byte, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrWorkerPolicy
	}
	f := os.NewFile(uintptr(fd), "fixed-worker-kernel-data")
	defer f.Close()
	var st unix.Statfs_t
	if unix.Fstatfs(fd, &st) != nil || int64(st.Type) != magic {
		return nil, ErrWorkerPolicy
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, ErrWorkerPolicy
	}
	return raw, nil
}

func namespace(name string) (unix.Stat_t, error) {
	// These are fixed kernel namespace handles, not untrusted symlink paths.
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return unix.Stat_t{}, ErrHostView
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &st) != nil || st.Ino == 0 {
		return st, ErrHostView
	}
	return st, nil
}

func ReadHost() (Host, error) {
	self, err := namespace("/proc/self/ns/mnt")
	if err != nil {
		return Host{}, ErrHostView
	}
	// Reduced capabilities cannot open PID1's namespace/root magic links:
	// doing so would require retaining broad CAP_SYS_PTRACE. Instead compare
	// complete kernel mount identities against PID1's readable mountinfo. A
	// cloned namespace has different mount IDs; chroot changes visible roots.
	// The producer enters fixed PID1 namespace/root BEFORE dropping privileges.
	initRaw, err := fixedKernelRead("/proc/1/mountinfo", diskusage.MountInfoBytesMax, unix.PROC_SUPER_MAGIC)
	if err != nil {
		return Host{}, ErrHostView
	}
	initInventory, err := diskusage.ParseMountInfo(bytes.NewReader(initRaw))
	if err != nil {
		return Host{}, ErrHostView
	}
	current, err := diskusage.ReadInventory()
	if err != nil || !current.MountListComplete || current.BindingSHA != initInventory.BindingSHA {
		return Host{}, ErrHostView
	}
	raw, err := fixedKernelRead("/proc/sys/kernel/random/boot_id", 128, unix.PROC_SUPER_MAGIC)
	h := Host{BootID: strings.TrimSpace(string(raw)), NamespaceID: strconv.FormatUint(uint64(self.Dev), 10) + ":" + strconv.FormatUint(self.Ino, 10)}
	if err != nil || ValidateHost(h) != nil {
		return Host{}, ErrHostView
	}
	return h, nil
}

func ReadHostInventory() (Inventory, error) {
	h, err := ReadHost()
	if err != nil {
		return Inventory{}, err
	}
	i, err := diskusage.ReadInventory()
	if err != nil {
		return Inventory{}, err
	}
	again, err := ReadHost()
	if err != nil || again != h {
		return Inventory{}, ErrHostView
	}
	return Inventory{Host: h, Mounts: i}, nil
}

// Setting process-wide rlimits belongs only in the isolated fixed worker,
// never in the HTTP executor. The unit enforces independent native deadlines.
func HardenWorker() error {
	if os.Geteuid() != 0 {
		return ErrWorkerPolicy
	}
	unix.Umask(0077)
	for resource, value := range map[int]uint64{unix.RLIMIT_CORE: 0, unix.RLIMIT_NOFILE: 2048, unix.RLIMIT_FSIZE: 1 << 30} {
		var prior unix.Rlimit
		if unix.Getrlimit(resource, &prior) != nil {
			return ErrWorkerPolicy
		}
		wanted := min(prior.Max, value)
		if resource == unix.RLIMIT_NOFILE && wanted < 2048 || resource == unix.RLIMIT_FSIZE && wanted < 1<<30 {
			return ErrWorkerPolicy
		}
		if unix.Setrlimit(resource, &unix.Rlimit{Cur: wanted, Max: wanted}) != nil {
			return ErrWorkerPolicy
		}
	}
	return nil
}

// Check every runtime thread. A single Capset or Setns on a live Go thread
// cannot establish process-wide privilege/namespace policy.
func threadPolicy(host Host) (int, error) {
	dir, err := os.Open("/proc/self/task")
	if err != nil {
		return 0, ErrWorkerPolicy
	}
	defer dir.Close()
	names, err := dir.Readdirnames(65)
	if err != nil && !errors.Is(err, io.EOF) || len(names) == 0 || len(names) > 32 {
		return 0, ErrWorkerPolicy
	}
	for _, tid := range names {
		if !CanonicalInteger(tid, true) {
			return 0, ErrWorkerPolicy
		}
		raw, err := fixedKernelRead("/proc/self/task/"+tid+"/status", 16384, unix.PROC_SUPER_MAGIC)
		if err != nil {
			return 0, err
		}
		fields := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		for scanner.Scan() {
			if k, v, ok := strings.Cut(scanner.Text(), ":"); ok {
				fields[k] = strings.TrimSpace(v)
			}
		}
		if scanner.Err() != nil {
			return 0, ErrWorkerPolicy
		}
		for _, name := range []string{"CapBnd", "CapPrm", "CapEff"} {
			if fields[name] != "0000000000000004" {
				return 0, ErrWorkerPolicy
			}
		}
		for _, name := range []string{"CapInh", "CapAmb"} {
			if fields[name] != "0000000000000000" {
				return 0, ErrWorkerPolicy
			}
		}
		if fields["NoNewPrivs"] != "1" {
			return 0, ErrWorkerPolicy
		}
		st, err := namespace("/proc/self/task/" + tid + "/ns/mnt")
		if err != nil || strconv.FormatUint(uint64(st.Dev), 10)+":"+strconv.FormatUint(st.Ino, 10) != host.NamespaceID {
			return 0, ErrHostView
		}
	}
	return len(names), nil
}

func VerifyWorker(ctx context.Context, id string, inventory bool) (Policy, error) {
	var out Policy
	if ctx.Err() != nil || os.Geteuid() != 0 {
		return out, ErrWorkerPolicy
	}
	unit, err := UnitName(id, inventory)
	if err != nil {
		return out, err
	}
	host, err := ReadHost()
	if err != nil {
		return out, err
	}
	threads, err := threadPolicy(host)
	if err != nil {
		return out, err
	}
	raw, err := fixedKernelRead("/proc/self/cgroup", 4096, unix.PROC_SUPER_MAGIC)
	wanted := "/system.slice/" + unit
	if err != nil || strings.TrimSpace(string(raw)) != "0::"+wanted {
		return out, ErrWorkerPolicy
	}
	out = Policy{Host: host, Cgroup: wanted, Threads: threads, Capabilities: "CAP_DAC_READ_SEARCH", NoNewPrivileges: true}
	for file, value := range map[string]string{"memory.max": "536870912", "memory.high": "402653184", "memory.swap.max": "0", "pids.max": "32", "io.weight": "default 10"} {
		data, err := fixedKernelRead("/sys/fs/cgroup"+wanted+"/"+file, 256, unix.CGROUP2_SUPER_MAGIC)
		if err != nil || strings.TrimSpace(string(data)) != value {
			return Policy{}, ErrWorkerPolicy
		}
	}
	cpu, err := fixedKernelRead("/sys/fs/cgroup"+wanted+"/cpu.max", 256, unix.CGROUP2_SUPER_MAGIC)
	if err != nil || strings.TrimSpace(string(cpu)) != "20000 100000" {
		return Policy{}, ErrWorkerPolicy
	}
	var fds, bytes, core unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &fds) != nil || unix.Getrlimit(unix.RLIMIT_FSIZE, &bytes) != nil || unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || fds.Cur != 2048 || fds.Max != 2048 || bytes.Cur != 1<<30 || bytes.Max != 1<<30 || core.Cur != 0 || core.Max != 0 {
		return Policy{}, ErrWorkerPolicy
	}
	out.CPUQuota = "20000 100000"
	out.MemoryMax = "536870912"
	out.MemoryHigh = "402653184"
	out.MemorySwapMax = "0"
	out.TasksMax = "32"
	out.IOWeight = "default 10"
	out.FileDescriptorsMax = fds.Max
	out.FileBytesMax = bytes.Max
	return out, nil
}
