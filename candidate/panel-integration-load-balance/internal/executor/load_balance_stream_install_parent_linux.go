//go:build linux

package executor

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamInstallChildMemory = int64(256 << 20)
const loadBalanceStreamInstallHostReserve = int64(512 << 20)

// The original parent and account child have the SAME five minimal permitted
// capabilities, so the child can observe its actual parent under Linux's
// capability/ptrace rules without CAP_SYS_PTRACE. All IDs remain Root solely
// for the bounded installer; the eventual traffic process has no capabilities.
// With NNP and seccomp setup, systemd can remove CAP_SETUID from permitted and
// effective sets unless it is explicitly ambient. Both fixed units request
// exactly that one inheritable/ambient bit; the five-capability ceiling is
// unchanged. Verify the actual sets, never just CapabilityBoundingSet.
func streamInstallRootCapabilities(raw []byte) bool {
	if !streamAccountParentRootStatus(raw) {
		return false
	}
	want := map[string]uint64{"CapInh": 0x80, "CapPrm": 0xcd, "CapEff": 0xcd, "CapBnd": 0xcd, "CapAmb": 0x80}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		expected, known := want[key]
		if !ok || !known {
			continue
		}
		fields := strings.Fields(value)
		if seen[key] || len(fields) != 1 {
			return false
		}
		seen[key] = true
		bits, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || bits != expected {
			return false
		}
	}
	return len(seen) == len(want)
}

func checkLoadBalanceStreamInstallParentKernel(ctx context.Context, job string) error {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return errLoadBalanceStreamInstallationGate
	}
	unit, err := loadbalancestream.AccountParentUnit(job)
	if err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start, e1 := moduleProcessStart("/proc", os.Getpid())
	status, e2 := streamAccountParentProc("/proc/self/status", 65536)
	group, e3 := streamAccountParentProc("/proc/self/cgroup", 4096)
	if e1 != nil || e2 != nil || e3 != nil || start == 0 || !streamInstallRootCapabilities(status) || string(group) != "0::/system.slice/"+unit+"\n" {
		return errLoadBalanceStreamInstallationGate
	}
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NoNewPrivileges,Slice")
	if err != nil || !streamAccountParentUnitState([]byte(raw), loadbalancestream.AccountChildPermit{JobID: job, ParentPID: uint32(os.Getpid())}) {
		return errLoadBalanceStreamInstallationGate
	}
	after, err := moduleProcessStart("/proc", os.Getpid())
	endStatus, e2 := streamAccountParentProc("/proc/self/status", 65536)
	endGroup, e3 := streamAccountParentProc("/proc/self/cgroup", 4096)
	if err != nil || e2 != nil || e3 != nil || start != after || !streamInstallRootCapabilities(endStatus) || string(endGroup) != string(group) || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

// Parent+child may overlap. Reserve both unchanged 256MiB hard caps plus a
// separate 512MiB host reserve before account creation, not just an individual
// process's observed RSS. This is a prerequisite, never a host reservation or
// a reason to stop existing services, drop caches or adjust kernel policy.
func loadBalanceStreamInstallMemoryAdmission(raw []byte) error {
	total, used, ok := parseMemoryMetric(raw)
	if !ok || total-used < uint64(2*loadBalanceStreamInstallChildMemory+loadBalanceStreamInstallHostReserve) {
		return loadbalancestream.ErrService
	}
	return nil
}
