//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamStoppedProcess struct {
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid"`
	StartTime uint64 `json:"start_time"`
}

// Produced ONLY by this original QUIT path, never from an inactive unit alone.
// The pidfds remain held until the original controller has retained its bytes.
type loadBalanceStreamStoppedObservation struct {
	Format                   int                               `json:"format"`
	InvocationID             string                            `json:"invocation_id"`
	AccountUID               uint32                            `json:"account_uid"`
	AccountGID               uint32                            `json:"account_gid"`
	EngineSHA256             string                            `json:"engine_sha256"`
	FinalExitSHA256          string                            `json:"final_exit_sha256"`
	FinalExitProperties      string                            `json:"final_exit_properties"`
	OriginalProcesses        []loadBalanceStreamStoppedProcess `json:"original_processes"`
	MemoryEvents             loadBalanceStreamMemoryEvents     `json:"memory_events"`
	OriginalQUITObserved     bool                              `json:"original_quit_observed"`
	EmptyCgroupBeforeCleanup bool                              `json:"empty_cgroup_before_cleanup"`
	ManagerCleanupObserved   bool                              `json:"manager_cleanup_observed"`
	prior                    *loadBalanceStreamServiceObservation
	publication              *loadBalanceStreamConfigurationPublication
	owner                    *loadBalanceStreamControlOwner
}

// A closed descriptor, a reused PID or a missing proc path is NOT evidence
// of exit. Readiness must come from the original still-held kernel pidfd.
func streamOriginalProcessExited(p *loadBalanceStreamProcessWitness) (bool, error) {
	if p == nil || p.pidfd < 0 || p.proc == nil || p.before == nil || p.PID < 2 || p.StartTime == 0 {
		return false, loadbalancestream.ErrService
	}
	poll := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil || poll[0].Revents & ^int16(unix.POLLIN|unix.POLLHUP) != 0 {
		return false, loadbalancestream.ErrService
	}
	if n == 0 && poll[0].Revents == 0 {
		return false, nil
	}
	if n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		return false, loadbalancestream.ErrService
	}
	return true, nil
}

func streamManagedServiceInactive(ctx context.Context, originalInvocation string) bool {
	properties, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
	if err != nil || properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" ||
		properties["MainPID"] != "0" || properties["ControlPID"] != "0" || properties["ExecMainStatus"] != "0" || properties["Result"] != "success" {
		return false
	}
	switch properties["LoadState"] {
	case "not-found":
		return properties["InvocationID"] == ""
	case "loaded":
		return properties["InvocationID"] == originalInvocation || properties["InvocationID"] == ""
	}
	return false
}

func (s *loadBalanceStreamStoppedObservation) originalProcessesExited() bool {
	if s == nil || s.prior == nil || len(s.OriginalProcesses) != 2 || len(s.prior.Processes) != 2 {
		return false
	}
	for i, process := range s.prior.Processes {
		want := s.OriginalProcesses[i]
		if process == nil || process.PID != want.PID || process.ParentPID != want.ParentPID || process.StartTime != want.StartTime {
			return false
		}
		exited, err := streamOriginalProcessExited(process)
		if err != nil || !exited {
			return false
		}
	}
	return true
}

func (s *loadBalanceStreamStoppedObservation) current(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Format != 1 || !s.OriginalQUITObserved ||
		!s.EmptyCgroupBeforeCleanup || !s.ManagerCleanupObserved || s.publication == nil || s.owner == nil ||
		!s.publication.serviceIssued || !s.publication.stopCleanupIssued || !s.originalProcessesExited() ||
		!streamStoppedExitMatches([]byte(s.FinalExitProperties), s.InvocationID) || core.Hash(s.FinalExitProperties) != s.FinalExitSHA256 {
		return loadbalancestream.ErrService
	}
	_, plan, err := s.publication.servicePlanOwned(ctx, s.owner)
	if err != nil || plan.Service.ShouldRun || s.prior.InvocationID != s.InvocationID ||
		s.prior.AccountUID != s.AccountUID || s.prior.AccountGID != s.AccountGID ||
		s.prior.EngineSHA256 != s.EngineSHA256 || s.prior.MemoryEvents != s.MemoryEvents ||
		!streamManagedServiceInactive(ctx, s.InvocationID) {
		return loadbalancestream.ErrService
	}
	// If the dead cgroup still exists it must be the original empty one.
	// Its disappearance does not excuse any still-live original process.
	info, err := os.Lstat("/sys/fs/cgroup/system.slice/" + loadbalancestream.ServiceUnitName)
	if err == nil {
		if !os.SameFile(info, s.prior.cgroupBefore) {
			return loadbalancestream.ErrService
		}
		raw, err := readLoadBalanceStreamCgroupFile(s.prior.cgroup, "cgroup.procs", 512)
		if err != nil || len(raw) != 0 {
			return loadbalancestream.ErrService
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return loadbalancestream.ErrService
	}
	return nil
}

func (s *loadBalanceStreamStoppedObservation) bytes(ctx context.Context) ([]byte, error) {
	if s.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) == 0 || len(raw) > 16384 || s.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	return append(raw, '\n'), nil
}

// ONE QUIT to the original master; then READ ONLY until every original
// process exits normally with an unchanged OOM census. No TERM/KILL, forced
// drain, manager restart or fallback is issued. Only the already-empty unit
// is stopped afterwards to release its retained manager/cgroup metadata.
func (p *loadBalanceStreamConfigurationPublication) stopOwned(ctx context.Context, w *loadBalanceStreamControlOwner) (*loadBalanceStreamStoppedObservation, error) {
	if p == nil || p.serviceIssued || p.stopCleanupIssued || !p.serviceEgressCurrent(ctx) {
		return nil, loadbalancestream.ErrService
	}
	seed, plan, err := p.servicePlanOwned(ctx, w)
	if err != nil || plan.Service.ShouldRun || plan.Service.Retiring.ActiveEntries == 0 || p.store.first || p.store.priorService == nil {
		return nil, loadbalancestream.ErrService
	}
	prior := p.store.priorService
	if prior.current(ctx) != nil || len(prior.Processes) != 2 || prior.plan.Current.SHA256 != seed.BeforeRuntimeSHA256 ||
		verifyLoadBalanceStreamConfigurationMarkers(ctx, prior, seed.Before) != nil {
		return nil, loadbalancestream.ErrService
	}
	var master *loadBalanceStreamProcessWitness
	result := &loadBalanceStreamStoppedObservation{Format: 1, InvocationID: prior.InvocationID,
		AccountUID: prior.AccountUID, AccountGID: prior.AccountGID, EngineSHA256: prior.EngineSHA256,
		MemoryEvents: prior.MemoryEvents, prior: prior, publication: p, owner: w}
	for _, process := range prior.Processes {
		result.OriginalProcesses = append(result.OriginalProcesses, loadBalanceStreamStoppedProcess{process.PID, process.ParentPID, process.StartTime})
		if process.PID == prior.MainPID {
			master = process
		}
	}
	if master == nil || !master.current(w.gate.installed.engine, prior.AccountUID, prior.AccountGID) || prior.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	if _, _, err := p.servicePlanOwned(ctx, w); err != nil {
		return nil, loadbalancestream.ErrService
	}
	p.serviceIssued = true
	if err := unix.PidfdSendSignal(master.pidfd, unix.SIGQUIT, nil, 0); err != nil {
		return nil, loadbalancestream.ErrService
	}
	result.OriginalQUITObserved = true
	bounded, cancel := context.WithTimeout(ctx, time.Duration(loadbalancestream.RuntimeDrainSeconds+30)*time.Second)
	defer cancel()
	for {
		if _, _, err := p.servicePlanOwned(bounded, w); err != nil {
			return nil, loadbalancestream.ErrService
		}
		if result.originalProcessesExited() {
			exit, err := programQueueCommand(bounded, "/usr/bin/systemctl", "show", loadbalancestream.ServiceUnitName, "--property="+streamStoppedExitProperties)
			if err != nil || !streamStoppedExitMatches([]byte(exit), prior.InvocationID) {
				return nil, loadbalancestream.ErrService
			}
			held, e1 := prior.cgroup.Stat()
			visible, e2 := os.Lstat("/sys/fs/cgroup/system.slice/" + loadbalancestream.ServiceUnitName)
			pids, e3 := readLoadBalanceStreamCgroupFile(prior.cgroup, "cgroup.procs", 512)
			rawEvents, e4 := readLoadBalanceStreamCgroupFile(prior.cgroup, "memory.events", 4096)
			events, e5 := decodeStreamMemoryEvents(rawEvents)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(pids) != 0 ||
				!os.SameFile(prior.cgroupBefore, held) || !os.SameFile(held, visible) ||
				events != prior.MemoryEvents || !prior.limitsCurrent() || observeStreamServiceIPPolicy(bounded, prior.plan) != nil {
				return nil, loadbalancestream.ErrService
			}
			result.FinalExitProperties = exit
			result.FinalExitSHA256 = core.Hash(exit)
			result.EmptyCgroupBeforeCleanup = true
			if _, _, err := p.servicePlanOwned(bounded, w); err != nil || !result.originalProcessesExited() {
				return nil, loadbalancestream.ErrService
			}
			p.stopCleanupIssued = true
			cleanup, done := context.WithTimeout(bounded, 10*time.Second)
			_, err = programQueueCommand(cleanup, "/usr/bin/systemctl", "stop", loadbalancestream.ServiceUnitName)
			done()
			if err != nil || !streamManagedServiceInactive(bounded, prior.InvocationID) {
				return nil, loadbalancestream.ErrService
			}
			result.ManagerCleanupObserved = true
			if result.current(bounded) != nil {
				return nil, loadbalancestream.ErrService
			}
			return result, nil
		}
		select {
		case <-bounded.Done():
			return nil, loadbalancestream.ErrService
		case <-time.After(100 * time.Millisecond):
		}
	}
}
