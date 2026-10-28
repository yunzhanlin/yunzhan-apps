//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// This private witness belongs to ONE live Root preparer and its held original
// generation. It is never reconstructed from a request, deserialized seed or a
// successful old journal, and cannot resume an interrupted attempt.
type loadBalanceStreamColdBootWitness struct {
	record     loadbalancestream.ColdBootRecord
	generation *loadBalanceStreamHeldGeneration
	uid        uint32
}

func streamColdUnitAbsent(state map[string]string) bool {
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "MainPID", "ControlPID", "ExecMainStatus", "Result", "InvocationID"} {
		if _, exists := state[key]; !exists {
			return false
		}
	}
	return state["LoadState"] == "not-found" && state["ActiveState"] == "inactive" && state["SubState"] == "dead" &&
		state["MainPID"] == "0" && state["ControlPID"] == "0" && state["InvocationID"] == "" &&
		state["ExecMainStatus"] == "0" && state["Result"] == "success"
}

// This is only a read-side eligibility observation. It cannot create a grant,
// replay a request or recover anything. A subsequent normal mutation still
// needs the original controller's fresh actor, lease and cold-boot witnesses.
func streamColdBootWorkspaceCurrent(ctx context.Context, installed *loadBalanceStreamInstalledContext, generation *loadBalanceStreamHeldGeneration, previousBoot string) error {
	if ctx == nil || ctx.Err() != nil || installed == nil || generation == nil || !streamEgressBootID(previousBoot) ||
		installed.current(ctx) != nil || generation.current(ctx) != nil {
		return loadbalancestream.ErrService
	}
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	currentBoot := strings.TrimSuffix(string(boot), "\n")
	if err != nil || !streamEgressBootID(currentBoot) || currentBoot == previousBoot {
		return loadbalancestream.ErrService
	}
	absent, err := holdLoadBalanceStreamAbsentEgressReadOnly(ctx)
	if err != nil {
		return loadbalancestream.ErrService
	}
	defer absent.close()
	if absent.bootID != currentBoot {
		return loadbalancestream.ErrService
	}
	for n := 0; n < 2; n++ {
		unit, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || !streamColdUnitAbsent(unit) || streamColdUIDAbsent(ctx, installed.identity.UID) != nil ||
			absent.current(ctx) != nil || generation.current(ctx) != nil || installed.current(ctx) != nil {
			return loadbalancestream.ErrService
		}
	}
	return nil
}

// Check every credential, including saved/fs UID. A partial/malformed status is
// not evidence of absence. No process name, command line or saved PID is used.
func streamColdStatusUIDAbsent(raw []byte, uid uint32) bool {
	if uid < 100 || uid >= 1000 || len(raw) == 0 || len(raw) > 65536 || raw[len(raw)-1] != '\n' || strings.ContainsRune(string(raw), 0) {
		return false
	}
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if seen {
			return false
		}
		seen = true
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return false
		}
		for _, field := range fields {
			id, err := strconv.ParseUint(field, 10, 32)
			if err != nil || strconv.FormatUint(id, 10) != field || uint32(id) == uid {
				return false
			}
		}
	}
	return seen
}

// A bounded COMPLETE native process census, not a scan of cgroup.procs alone:
// an orphaned same-UID process outside the old service must also deny recovery.
// Read-only fixed procfs, no fixture path/callback or caller PID is accepted.
func streamColdUIDAbsent(ctx context.Context, uid uint32) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || uid < 100 || uid >= 1000 {
		return loadbalancestream.ErrService
	}
	dir, err := os.OpenFile("/proc", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return loadbalancestream.ErrService
	}
	defer dir.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return loadbalancestream.ErrService
	}
	entries, err := dir.ReadDir(65537)
	if err != nil && err != io.EOF || len(entries) > 65536 {
		return loadbalancestream.ErrService
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return loadbalancestream.ErrService
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 31)
		if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != entry.Name() {
			continue // Only kernel-created numeric process entries are in scope.
		}
		fd, err := unix.Openat(int(dir.Fd()), entry.Name()+"/status", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			continue // The process has exited; unreadable LIVE processes still fail.
		}
		if err != nil {
			return loadbalancestream.ErrService
		}
		file := os.NewFile(uintptr(fd), "held-proc-status")
		var currentFS unix.Statfs_t
		raw, readErr := io.ReadAll(io.LimitReader(file, 65537))
		fsErr := unix.Fstatfs(fd, &currentFS)
		file.Close()
		if readErr != nil || fsErr != nil || currentFS.Type != unix.PROC_SUPER_MAGIC || !streamColdStatusUIDAbsent(raw, uid) {
			return loadbalancestream.ErrService
		}
	}
	if ctx.Err() != nil {
		return loadbalancestream.ErrService
	}
	return nil
}

func (w *loadBalanceStreamColdBootWitness) identityCurrent(ctx context.Context, s *loadBalanceStreamConfigurationStore) error {
	if ctx == nil || ctx.Err() != nil || w == nil || s == nil || s.released || s.first || s.installed == nil || s.generation == nil || w.generation != s.generation ||
		w.uid != s.installed.identity.UID || s.generation.current(ctx) != nil || core.Hash(string(s.generation.raw)) != w.record.OriginalGenerationSHA256 ||
		s.generation.value.SeedSHA256 != w.record.OriginalSeedSHA256 || s.generation.value.ServiceObservationSHA256 != w.record.OriginalServiceSHA256 {
		return loadbalancestream.ErrService
	}
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || !streamEgressBootID(w.record.PreviousBootID) || !streamEgressBootID(w.record.BootID) ||
		w.record.PreviousBootID == w.record.BootID || string(boot) != w.record.BootID+"\n" {
		return loadbalancestream.ErrService
	}
	receipt, err := s.recordedServiceReceipt(ctx)
	if err != nil || receipt.Egress.BootID != w.record.PreviousBootID {
		return loadbalancestream.ErrService
	}
	return nil
}

func (w *loadBalanceStreamColdBootWitness) current(ctx context.Context, s *loadBalanceStreamConfigurationStore) error {
	if w.identityCurrent(ctx, s) != nil {
		return loadbalancestream.ErrService
	}
	unit, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
	if err != nil || !streamColdUnitAbsent(unit) || streamColdUIDAbsent(ctx, w.uid) != nil {
		return loadbalancestream.ErrService
	}
	return nil
}

func (s *loadBalanceStreamConfigurationStore) observeColdBoot(ctx context.Context) error {
	if s == nil || s.first || s.priorColdBoot != nil || s.priorCaptured || s.priorService != nil || s.priorStopped || s.generation == nil || s.beforeCurrent(ctx) != nil {
		return loadbalancestream.ErrService
	}
	receipt, err := s.recordedServiceReceipt(ctx)
	if err != nil {
		return loadbalancestream.ErrService
	}
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	current := strings.TrimSuffix(string(boot), "\n")
	if err != nil || !streamEgressBootID(current) || !streamEgressBootID(receipt.Egress.BootID) || receipt.Egress.BootID == current {
		return loadbalancestream.ErrService
	}
	w := &loadBalanceStreamColdBootWitness{generation: s.generation, uid: s.installed.identity.UID,
		record: loadbalancestream.ColdBootRecord{Format: 1, PreviousBootID: receipt.Egress.BootID, BootID: current,
			OriginalGenerationSHA256: core.Hash(string(s.generation.raw)), OriginalSeedSHA256: s.generation.value.SeedSHA256,
			OriginalServiceSHA256: s.generation.value.ServiceObservationSHA256}}
	if w.current(ctx, s) != nil {
		return loadbalancestream.ErrService
	}
	s.priorColdBoot, s.priorCaptured = w, true
	return nil
}
