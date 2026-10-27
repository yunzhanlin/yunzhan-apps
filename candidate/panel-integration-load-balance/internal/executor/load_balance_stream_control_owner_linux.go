//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The original traffic controller is owned by the EXISTING fixed executor
// process. It does not expand the account-child's five capabilities, introduce
// a new privileged parent unit, or accept an owner/PID from a request/receipt.
// This live prerequisite STILL does not prove service/network/config health.
type loadBalanceStreamControlOwner struct {
	gate     *loadBalanceStreamControlGate
	lifetime *memcachedUnixRuntimeLease
	mutation *loadBalanceStreamMutationLease
	process  *moduleApplyOwner
	service  *Service
}

// Actual own-fd kernel FLOCK evidence only. A name or an empty lock file cannot
// substitute for the current process holding the original SH/EX lease.
func streamControlLeaseFDInfo(raw []byte, pid int, info os.FileInfo, exclusive bool) bool {
	if info == nil || pid < 2 || len(raw) == 0 || len(raw) > 8192 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() != 0 || st.Uid != 0 || st.Nlink != 1 {
		return false
	}
	mode := "READ"
	if exclusive {
		mode = "WRITE"
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		value = strings.TrimSpace(value)
		switch key {
		case "pos":
			if value != "0" {
				return false
			}
		case "flags":
			flags, err := strconv.ParseUint(value, 8, 32)
			if err != nil || flags&3 != unix.O_RDONLY && flags&3 != unix.O_RDWR {
				return false
			}
		case "mnt_id":
			id, err := strconv.ParseUint(value, 10, 64)
			if err != nil || id == 0 || strconv.FormatUint(id, 10) != value {
				return false
			}
		case "ino":
			if value != strconv.FormatUint(st.Ino, 10) {
				return false
			}
		case "lock":
			v := strings.Fields(value)
			if len(v) != 8 || v[0] != "1:" || v[1] != "FLOCK" || v[2] != "ADVISORY" || v[3] != mode || v[4] != strconv.Itoa(pid) || v[6] != "0" || v[7] != "EOF" {
				return false
			}
			device := strings.Split(v[5], ":")
			if len(device) != 3 {
				return false
			}
			major, e1 := strconv.ParseUint(device[0], 16, 32)
			minor, e2 := strconv.ParseUint(device[1], 16, 32)
			inode, e3 := strconv.ParseUint(device[2], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil || major != uint64(unix.Major(uint64(st.Dev))) || minor != uint64(unix.Minor(uint64(st.Dev))) || inode != st.Ino {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 5
}

func streamControlHeldLease(file *os.File, exclusive bool) bool {
	if file == nil {
		return false
	}
	before, err := file.Stat()
	if err != nil {
		return false
	}
	raw, err := streamAccountParentProc(filepath.Join("/proc/self/fdinfo", strconv.FormatUint(uint64(file.Fd()), 10)), 8192)
	after, e2 := file.Stat()
	return err == nil && e2 == nil && geoStoreStableInfo(before, after) && streamControlLeaseFDInfo(raw, os.Getpid(), before, exclusive)
}

func (w *loadBalanceStreamControlOwner) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || w.gate == nil || w.gate.current(ctx) != nil || w.lifetime == nil || !w.lifetime.current() || w.mutation == nil || !w.mutation.current() || w.process == nil || w.process.PID != os.Getpid() || w.service == nil || w.service.Config.SystemRoot != "/" {
		return errLoadBalanceStreamInstallationGate
	}
	j := w.gate.journal
	if j == nil || !j.creator || j.unknown || j.lock == nil || !streamControlHeldLease(j.lock, true) || !streamControlHeldLease(w.lifetime.file.file, false) || !streamControlHeldLease(w.mutation.file, true) {
		return errLoadBalanceStreamInstallationGate
	}
	if w.service.authorizeModuleCandidate(ctx, filepath.Join(j.path, "run.lock"), w.process) != nil || w.gate.current(ctx) != nil || !w.lifetime.current() || !w.mutation.current() {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

func bindLoadBalanceStreamControlOwner(ctx context.Context, gate *loadBalanceStreamControlGate, lifetime *memcachedUnixRuntimeLease, mutation *loadBalanceStreamMutationLease) (*loadBalanceStreamControlOwner, error) {
	if gate == nil || gate.current(ctx) != nil || lifetime == nil || !lifetime.current() || mutation == nil || !mutation.current() {
		return nil, errLoadBalanceStreamInstallationGate
	}
	_, records, _, err := gate.journal.original(ctx)
	if err != nil || len(records) != 1 {
		return nil, errLoadBalanceStreamInstallationGate
	}
	process, err := currentModuleApplyOwner()
	if err != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	w := &loadBalanceStreamControlOwner{gate: gate, lifetime: lifetime, mutation: mutation, process: process, service: New(Config{})}
	if w.current(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	return w, nil
}
