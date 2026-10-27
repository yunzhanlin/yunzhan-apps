//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

// The historical 32-byte query prefix is accepted by older supported kernels;
// later optional type/link/revision fields are zero. Both supported native
// architectures have the same explicitly checked UAPI offsets. QUERY ONLY:
// there is no BPF load, attach, detach, map mutation or capability adjustment.
type loadBalanceStreamBPFQuery struct {
	TargetFD     uint32
	AttachType   uint32
	QueryFlags   uint32
	AttachFlags  uint32
	ProgramIDs   uint64
	ProgramCount uint32
	Reserved     uint32
}

func loadBalanceStreamCgroupBPFPrograms(directory *os.File, attach uint32) ([]uint32, error) {
	return loadBalanceStreamCgroupBPFProgramsWithFlags(directory, attach, unix.BPF_F_QUERY_EFFECTIVE)
}

func loadBalanceStreamCgroupBPFProgramsWithFlags(directory *os.File, attach, flags uint32) ([]uint32, error) {
	if directory == nil || attach != unix.BPF_CGROUP_INET_INGRESS && attach != unix.BPF_CGROUP_INET_EGRESS || flags != 0 && flags != unix.BPF_F_QUERY_EFFECTIVE || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || directory.Fd() > 1<<31-1 {
		return nil, loadbalancestream.ErrService
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, loadbalancestream.ErrService
	}
	var ids [64]uint32
	query := loadBalanceStreamBPFQuery{TargetFD: uint32(directory.Fd()), AttachType: attach, QueryFlags: flags, ProgramIDs: uint64(uintptr(unsafe.Pointer(&ids[0]))), ProgramCount: uint32(len(ids))}
	if unsafe.Sizeof(query) != 32 || unsafe.Offsetof(query.ProgramIDs) != 16 || unsafe.Offsetof(query.ProgramCount) != 24 {
		return nil, loadbalancestream.ErrService
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_QUERY), uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	runtime.KeepAlive(directory)
	runtime.KeepAlive(&ids)
	if errno != 0 || query.ProgramCount > uint32(len(ids)) || query.TargetFD != uint32(directory.Fd()) || query.AttachType != attach || query.QueryFlags != flags || query.Reserved != 0 {
		return nil, loadbalancestream.ErrService
	}
	out := append([]uint32{}, ids[:query.ProgramCount]...)
	seen := map[uint32]bool{}
	for _, id := range out {
		if id == 0 || seen[id] {
			return nil, loadbalancestream.ErrService
		}
		seen[id] = true
	}
	return out, nil
}

func readLoadBalanceStreamCgroupFile(directory *os.File, name string, maximum int64) ([]byte, error) {
	allowed := map[string]bool{"cgroup.controllers": true, "memory.max": true, "memory.high": true, "memory.swap.max": true, "pids.max": true, "cpu.max": true, "cgroup.procs": true, "memory.events": true, "memory.current": true}
	if directory == nil || !allowed[name] || maximum < 1 || maximum > 65536 {
		return nil, loadbalancestream.ErrService
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, loadbalancestream.ErrService
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, loadbalancestream.ErrService
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, loadbalancestream.ErrService
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, loadbalancestream.ErrService
	}
	return raw, nil
}

func loadBalanceStreamRequiredControllers(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4096 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, name := range strings.Fields(string(raw)) {
		if seen[name] || len(seen) >= 64 || name == "" {
			return false
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c == '_') {
				return false
			}
		}
		seen[name] = true
	}
	return seen["memory"] && seen["pids"] && seen["cpu"]
}

// Actual fixed-host support/admission, NOT a service/enforcement witness. In
// particular a successful query with ZERO programs merely means the kernel
// supports the query; post-activation must prove the actual unit has matching
// inbound/outbound filters, limits, processes, sockets and forwarding probes.
// Permission failure is reported, never bypassed with new capabilities or a
// kernel-policy/threshold change.
func measureLoadBalanceStreamServiceFacts(ctx context.Context, installed *loadBalanceStreamInstalledContext) (loadbalancestream.ServiceFacts, error) {
	var empty loadbalancestream.ServiceFacts
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || installed == nil || installed.current(ctx) != nil {
		return empty, loadbalancestream.ErrService
	}
	raw, err := streamAccountParentProc("/proc/meminfo", 65536)
	if err != nil {
		return empty, err
	}
	total, used, ok := parseMemoryMetric(raw)
	if !ok || used > total || total-used > 1<<60 {
		return empty, loadbalancestream.ErrService
	}
	if threatIDSTrustedParents("/sys/fs", false) != nil {
		return empty, loadbalancestream.ErrService
	}
	directory, err := os.OpenFile("/sys/fs/cgroup", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, loadbalancestream.ErrService
	}
	defer directory.Close()
	controllers, err := readLoadBalanceStreamCgroupFile(directory, "cgroup.controllers", 4096)
	if err != nil || !loadBalanceStreamRequiredControllers(controllers) {
		return empty, loadbalancestream.ErrService
	}
	for _, attach := range []uint32{unix.BPF_CGROUP_INET_INGRESS, unix.BPF_CGROUP_INET_EGRESS} {
		if _, err := loadBalanceStreamCgroupBPFPrograms(directory, attach); err != nil {
			return empty, err
		}
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil || limit.Max < loadbalancestream.RuntimeOpenFiles {
		return empty, loadbalancestream.ErrService
	}
	nr, err := streamAccountParentProc("/proc/sys/fs/nr_open", 128)
	if err != nil {
		return empty, loadbalancestream.ErrService
	}
	maximum, err := strconv.ParseUint(strings.TrimSuffix(string(nr), "\n"), 10, 64)
	if err != nil || strconv.FormatUint(maximum, 10)+"\n" != string(nr) || maximum < loadbalancestream.RuntimeOpenFiles {
		return empty, loadbalancestream.ErrService
	}
	if limit.Max < maximum {
		maximum = limit.Max
	}
	facts := loadbalancestream.ServiceFacts{Validation: loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}, AvailableMemoryBytes: int64(total - used), HardOpenFiles: maximum, UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: installed.identity.UID, AccountGID: installed.identity.GID, AccountRecordSHA256: installed.accountSHA, NginxVersion: installed.engine.release.Version, NginxSHA256: installed.engine.binary.sha}
	// Custom panel/control ports and external TCP/UDP occupancy have NOT been
	// inferred here. The controller must census them before ValidateSet/plan.
	if installed.current(ctx) != nil || ctx.Err() != nil {
		return empty, loadbalancestream.ErrService
	}
	return facts, nil
}
