package executor

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"local/panel/internal/runtimecatalog"
)

const runtimePHPCompilerMemoryBytes uint64 = 1 << 30
const runtimePHPCompilerServiceReserve uint64 = 512 << 20

var errRuntimePHPCompilerMemoryIdentity = errors.New("PHP 编译内存策略缺少当前完整官方源码身份，未启动编译")
var errRuntimePHPCompilerMemoryInventory = errors.New("无法核实主机完整内存余量，未启动 PHP 大型源码编译")
var errRuntimePHPCompilerMemoryKernel = errors.New("PHP 大型源码编译需要固定 1 GiB、零交换的受限安装单元；当前内核限额不匹配，未启动编译")

// Only this exact internal error is retryable. Identity, inventory, kernel
// policy and malformed/unknown errors must never be turned into a wait or a
// successful admission. The original byte budgets are not changed.
type runtimePHPCompilerMemoryShortage struct{ message string }

func (e *runtimePHPCompilerMemoryShortage) Error() string { return e.message }

// A closed release decision, not a caller-supplied resource budget. Legacy
// installed versions and other runtime families keep their existing admission.
func runtimePHPCompilerNeedsMemoryAdmission(r runtimecatalog.Release) (bool, error) {
	spec, selected := runtimeMagicSpecification(r.ID)
	if !selected {
		return false, nil
	}
	official, found := runtimecatalog.Find(r.ID)
	if !found || official != r || r.Family != "php" || r.SHA256 != spec.archiveSHA {
		return false, errRuntimePHPCompilerMemoryIdentity
	}
	return true, nil
}

func runtimePHPCompilerHostMemory(raw []byte) (uint64, uint64, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return 0, 0, errRuntimePHPCompilerMemoryInventory
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "MemTotal:" && fields[0] != "MemAvailable:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, 0, errRuntimePHPCompilerMemoryInventory
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return 0, 0, errRuntimePHPCompilerMemoryInventory
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(kb, 10) != fields[1] || kb > ^uint64(0)/1024 {
			return 0, 0, errRuntimePHPCompilerMemoryInventory
		}
		values[fields[0]] = kb * 1024
	}
	total, haveTotal := values["MemTotal:"]
	available, haveAvailable := values["MemAvailable:"]
	if !haveTotal || !haveAvailable || total == 0 || available > total {
		return 0, 0, errRuntimePHPCompilerMemoryInventory
	}
	return total, available, nil
}

func runtimePHPCompilerMemoryAdmission(r runtimecatalog.Release, raw []byte) error {
	return runtimePHPCompilerMemoryAdmissionOwned(r, raw, 0)
}

// Only the worker's independently witnessed non-reclaimable charge can offset
// a host reservation. MemAvailable already includes reclaimable file cache.
func runtimePHPCompilerMemoryAdmissionOwned(r runtimecatalog.Release, raw []byte, ownNonReclaimable uint64) error {
	selected, err := runtimePHPCompilerNeedsMemoryAdmission(r)
	if err != nil || !selected {
		return err
	}
	_, available, err := runtimePHPCompilerHostMemory(raw)
	if err != nil {
		return err
	}
	if ownNonReclaimable > runtimePHPCompilerMemoryBytes {
		return errRuntimePHPCompilerMemoryKernel
	}
	required := runtimePHPCompilerMemoryBytes - ownNonReclaimable + runtimePHPCompilerServiceReserve
	if available < required {
		return &runtimePHPCompilerMemoryShortage{fmt.Sprintf("PHP %s 源码编译需要 1 GiB 总预算并为现有服务保留 512 MiB；当前可用 %d MiB，剩余预算与预留还需 %d MiB，未启动编译，请释放容量或在更大内存服务器安装", r.Version, available>>20, (required+(1<<20)-1)>>20)}
	}
	return nil
}

// No alternative, unbounded, soft-only or swap-backed policy is admitted.
// The actual kernel witness is read independently inside the selected worker.
func runtimePHPCompilerMemoryKernelPolicy(values map[string]string) error {
	expected := map[string]string{"memory.max": "1073741824\n", "memory.high": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"}
	if len(values) != len(expected) {
		return errRuntimePHPCompilerMemoryKernel
	}
	for key, want := range expected {
		if values[key] != want {
			return errRuntimePHPCompilerMemoryKernel
		}
	}
	return nil
}

func runtimePHPCompilerMemoryAncestor(maximum, current []byte) error {
	return runtimePHPCompilerMemoryAncestorOwned(maximum, current, 0)
}

// A parent's memory.current counts its child's entire existing charge,
// including cache. That is distinct from the host MemAvailable accounting.
func runtimePHPCompilerMemoryAncestorOwned(maximum, current []byte, ownCharged uint64) error {
	if ownCharged > runtimePHPCompilerMemoryBytes {
		return errRuntimePHPCompilerMemoryKernel
	}
	available, valid := compilerCgroupAvailable(maximum, current)
	if !valid {
		return errRuntimePHPCompilerMemoryKernel
	}
	if bytes.Equal(maximum, []byte("max\n")) {
		return nil
	}
	if available < runtimePHPCompilerMemoryBytes-ownCharged+runtimePHPCompilerServiceReserve {
		return &runtimePHPCompilerMemoryShortage{"PHP 编译所在的父级 cgroup 无法容纳剩余 1 GiB 总预算与 512 MiB 服务预留，未启动编译或提高上级限额"}
	}
	return nil
}

type runtimePHPCompilerOwnedMemory struct {
	Charged uint64
	// Conservative confirmed subset only: anonymous + shared memory. Do not
	// credit file cache, reclaimable slab or optional kernel-version fields.
	NonReclaimable uint64
}

func runtimePHPCompilerMemoryFootprint(currentRaw, statRaw []byte) (runtimePHPCompilerOwnedMemory, error) {
	var out runtimePHPCompilerOwnedMemory
	if len(currentRaw) < 2 || len(currentRaw) > 32 || currentRaw[len(currentRaw)-1] != '\n' || len(statRaw) == 0 || len(statRaw) > 65536 || statRaw[len(statRaw)-1] != '\n' || bytes.ContainsAny(statRaw, "\x00\r") {
		return out, errRuntimePHPCompilerMemoryKernel
	}
	text := string(currentRaw[:len(currentRaw)-1])
	charged, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(charged, 10) != text || charged > runtimePHPCompilerMemoryBytes {
		return out, errRuntimePHPCompilerMemoryKernel
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSuffix(string(statRaw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) == 0 || len(fields[0]) > 64 || len(values) >= 256 {
			return out, errRuntimePHPCompilerMemoryKernel
		}
		for _, char := range fields[0] {
			if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return out, errRuntimePHPCompilerMemoryKernel
			}
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return out, errRuntimePHPCompilerMemoryKernel
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != fields[1] {
			return out, errRuntimePHPCompilerMemoryKernel
		}
		values[fields[0]] = value
	}
	for _, key := range []string{"anon", "shmem"} {
		value, found := values[key]
		if !found || value > runtimePHPCompilerMemoryBytes {
			return out, errRuntimePHPCompilerMemoryKernel
		}
	}
	nonReclaimable := values["anon"] + values["shmem"]
	if nonReclaimable > charged {
		return out, errRuntimePHPCompilerMemoryKernel
	}
	return runtimePHPCompilerOwnedMemory{charged, nonReclaimable}, nil
}

// The true cgroup2 kernfs root is not a limited ancestor: its non-root-only
// memory/type interfaces do not exist. A delegated namespace root (a non-root
// inode), disabled controller, partial absence or read error is NOT equivalent.
func runtimePHPCompilerMemoryUncontrolledRoot(inode uint64, controllers []byte, maxAbsent, currentAbsent, typeAbsent bool) error {
	if inode != 1 || !maxAbsent || !currentAbsent || !typeAbsent || len(controllers) == 0 || len(controllers) > 4096 || controllers[len(controllers)-1] != '\n' || bytes.ContainsAny(controllers, "\x00\r") {
		return errRuntimePHPCompilerMemoryKernel
	}
	seen := map[string]bool{}
	for _, name := range strings.Fields(string(controllers)) {
		if len(name) == 0 || len(name) > 32 || seen[name] {
			return errRuntimePHPCompilerMemoryKernel
		}
		for _, char := range name {
			if char < 'a' || char > 'z' {
				return errRuntimePHPCompilerMemoryKernel
			}
		}
		seen[name] = true
	}
	if !seen["memory"] {
		return errRuntimePHPCompilerMemoryKernel
	}
	return nil
}
