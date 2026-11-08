//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

// Capture the ACTUAL old generation before writing a candidate. This is not
// reconstruction from a caller's PID or from a saved successful health flag.
// A previous retiring worker must be gone before a further reload is admitted.
func (s *loadBalanceStreamConfigurationStore) observePriorService(ctx context.Context, before []loadbalancestream.Entry, beforeRuntimeSHA string) error {
	if s == nil || s.released || s.priorCaptured || s.priorService != nil || s.priorStopped || s.priorColdBoot != nil || s.beforeCurrent(ctx) != nil {
		return loadbalancestream.ErrService
	}
	if s.first {
		if len(before) != 0 || s.generation != nil {
			return loadbalancestream.ErrService
		}
		state, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || state["LoadState"] != "not-found" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["MainPID"] != "0" || state["ControlPID"] != "0" || state["InvocationID"] != "" {
			return loadbalancestream.ErrService
		}
		s.priorCaptured = true
		return nil
	}
	if s.generation == nil || s.generation.current(ctx) != nil || !reflect.DeepEqual(s.generation.value.Entries, before) {
		return loadbalancestream.ErrService
	}
	raw, _, chain, err := s.generation.journal.original(ctx)
	if err != nil || !chain.Complete {
		return loadbalancestream.ErrService
	}
	prior, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || !reflect.DeepEqual(prior.After, before) {
		return loadbalancestream.ErrService
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, s.installed)
	if err != nil {
		return loadbalancestream.ErrService
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return loadbalancestream.ErrService
	}
	facts.Validation.PanelControlPorts = ports
	plan, err := loadbalancestream.RecordedControlServicePlan(prior, facts)
	if err != nil || plan.Current.SHA256 != beforeRuntimeSHA ||
		plan.SHA256 != prior.ServiceUnitSHA256 || plan.SHA256 != s.generation.value.ServiceUnitSHA256 {
		return loadbalancestream.ErrService
	}
	recorded, err := s.recordedServiceReceipt(ctx)
	if err != nil {
		return loadbalancestream.ErrService
	}
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || !streamEgressBootID(strings.TrimSuffix(string(boot), "\n")) {
		return loadbalancestream.ErrService
	}
	if string(boot) != recorded.Egress.BootID+"\n" {
		// A different kernel boot needs a fresh native absence witness. Never
		// fall back here after a same-boot crash or an unreadable observation.
		return s.observeColdBoot(ctx)
	}
	if !plan.ShouldRun {
		var stopped streamServiceRecordedStopped
		if recorded.State != "stopped" || json.Unmarshal(recorded.Native, &stopped) != nil ||
			stopped.AccountUID != s.installed.identity.UID || stopped.AccountGID != s.installed.identity.GID ||
			stopped.EngineSHA256 != s.installed.engine.binary.sha || !streamManagedServiceInactive(ctx, stopped.InvocationID) {
			return loadbalancestream.ErrService
		}
		state, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || state["LoadState"] != "not-found" || state["InvocationID"] != "" || s.beforeCurrent(ctx) != nil {
			return loadbalancestream.ErrService
		}
		s.priorStopped = true
		s.priorCaptured = true
		return nil
	}
	observed, err := observeLoadBalanceStreamService(ctx, s.installed, plan, false)
	if err != nil {
		return loadbalancestream.ErrService
	}
	if !streamServiceMatchesRecorded(observed, recorded) || verifyLoadBalanceStreamConfigurationMarkers(ctx, observed, before) != nil ||
		s.beforeCurrent(ctx) != nil || observed.current(ctx) != nil {
		observed.close()
		return loadbalancestream.ErrService
	}
	s.priorService = observed
	s.priorCaptured = true
	return nil
}

// Revalidate the SAME held preflight before any candidate filesystem effect.
// Observing a service above grants nothing; this fresh original phase/gate is
// separately mandatory and no process/inode is re-opened as a replacement.
func (s *loadBalanceStreamConfigurationStore) capturePriorService(ctx context.Context, w *loadBalanceStreamControlOwner, seed loadbalancestream.ControlSeed) error {
	if s == nil || s.released || !s.priorCaptured || s.egress == nil || s.beforeCurrent(ctx) != nil || w == nil || w.current(ctx) != nil ||
		s.installed != w.gate.installed || s.source != w.gate.source || s.lifetime != w.lifetime || s.mutation != w.mutation || s.original != w.gate.original {
		return loadbalancestream.ErrService
	}
	raw, err := w.configurationPhase(ctx, "configuration-intent")
	canonical, e2 := loadbalancestream.ControlSeedBytes(seed)
	if err != nil || e2 != nil || !bytes.Equal(raw, canonical) {
		return loadbalancestream.ErrService
	}
	if s.priorColdBoot != nil {
		if seed.ColdBoot == nil || *seed.ColdBoot != s.priorColdBoot.record || s.priorColdBoot.current(ctx, s) != nil {
			return loadbalancestream.ErrService
		}
	} else if seed.ColdBoot != nil {
		return loadbalancestream.ErrService
	}
	if s.priorService != nil {
		if s.first || s.priorStopped || s.priorColdBoot != nil || s.priorService.current(ctx) != nil || verifyLoadBalanceStreamConfigurationMarkers(ctx, s.priorService, seed.Before) != nil {
			return loadbalancestream.ErrService
		}
	} else {
		if !s.first && !s.priorStopped && s.priorColdBoot == nil {
			return loadbalancestream.ErrService
		}
		state, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || state["LoadState"] != "not-found" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["MainPID"] != "0" || state["ControlPID"] != "0" || state["InvocationID"] != "" {
			return loadbalancestream.ErrService
		}
	}
	return s.beforeCurrent(ctx)
}

// Current original authority AFTER atomic promotion. beforeCurrent deliberately
// cannot pass after nginx.conf changes; do not weaken that check or reconstruct
// its old file. Hold the original generation/leases and verify the actual new
// publication instead.
func (p *loadBalanceStreamConfigurationPublication) servicePlanOwned(ctx context.Context, w *loadBalanceStreamControlOwner) (loadbalancestream.ControlSeed, loadbalancestream.ServiceLaunchPlan, error) {
	seed, plan, err := p.activationPlan(ctx, w)
	if err != nil || p.store == nil || p.store.released {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	s := p.store
	if s.installed != w.gate.installed || s.source != w.gate.source || s.lifetime != w.lifetime || s.mutation != w.mutation ||
		s.original != w.gate.original || s.file != p.original || seed.Operation.RequestID != s.original.RequestID ||
		s.egress == nil || s.egress.current(ctx) != nil {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	if s.first {
		if s.generation != nil || s.priorService != nil || s.priorStopped || s.priorColdBoot != nil || seed.ColdBoot != nil || len(seed.Before) != 0 {
			return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
		}
	} else if s.generation == nil || s.generation.current(ctx) != nil || !reflect.DeepEqual(s.generation.value.Entries, seed.Before) {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	if s.priorColdBoot != nil {
		if seed.ColdBoot == nil || *seed.ColdBoot != s.priorColdBoot.record || s.priorService != nil || s.priorStopped ||
			s.priorColdBoot.identityCurrent(ctx, s) != nil || !p.serviceIssued && s.priorColdBoot.current(ctx, s) != nil {
			return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
		}
		// Once THIS original controller issued its single start, its own new
		// process is expected. Later receipt code independently pins/validates
		// that invocation; an old absence check cannot become a live receipt.
	} else if seed.ColdBoot != nil {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	return seed, plan, nil
}

func streamReloadSameOriginalService(prior, next *loadBalanceStreamServiceObservation) bool {
	return prior != nil && next != nil && prior.cgroup != nil && next.cgroup != nil &&
		prior.cgroupBefore != nil && next.cgroupBefore != nil && os.SameFile(prior.cgroupBefore, next.cgroupBefore) &&
		prior.MainPID == next.MainPID && prior.InvocationID == next.InvocationID &&
		prior.AccountUID == next.AccountUID && prior.AccountGID == next.AccountGID &&
		prior.EngineSHA256 == next.EngineSHA256 && prior.MemoryEvents == next.MemoryEvents
}

// This is a process-set join, not a claim that a new worker loaded the desired
// configuration. The old listener-close barrier and exact marker/listener
// observations below are independently required.
func streamReloadHasOneNewWorker(prior, next *loadBalanceStreamServiceObservation) bool {
	if prior == nil || next == nil || len(prior.Processes) != 2 || len(next.Processes) < 2 || len(next.Processes) > 3 || prior.MainPID != next.MainPID {
		return false
	}
	var old, originalMaster *loadBalanceStreamProcessWitness
	for _, process := range prior.Processes {
		if process == nil || process.StartTime == 0 {
			return false
		}
		if process.PID == prior.MainPID {
			if originalMaster != nil || process.ParentPID != 1 {
				return false
			}
			originalMaster = process
		} else {
			if old != nil || process.ParentPID != prior.MainPID {
				return false
			}
			old = process
		}
	}
	if old == nil || originalMaster == nil {
		return false
	}
	newWorkers, oldWorkers, masters := 0, 0, 0
	seen := map[int]bool{}
	for _, process := range next.Processes {
		if process == nil || process.StartTime == 0 || seen[process.PID] {
			return false
		}
		seen[process.PID] = true
		if process.PID == next.MainPID {
			if process.StartTime != originalMaster.StartTime || process.ParentPID != 1 {
				return false
			}
			masters++
		} else if process.ParentPID != next.MainPID {
			return false
		} else if process.PID == old.PID && process.StartTime == old.StartTime {
			oldWorkers++
		} else {
			newWorkers++
		}
	}
	return masters == 1 && newWorkers == 1 && oldWorkers <= 1
}

// ONE policy batch and ONE HUP to the original held master pidfd. No PID file,
// name-based signal, restart fallback, old-worker kill, retry or restoration is
// permitted. A failure after serviceIssued remains an unknown original effect.
func (p *loadBalanceStreamConfigurationPublication) reloadOwned(ctx context.Context, w *loadBalanceStreamControlOwner) (*loadBalanceStreamServiceObservation, error) {
	if p == nil || p.serviceIssued || !p.serviceEgressCurrent(ctx) {
		return nil, loadbalancestream.ErrService
	}
	seed, plan, err := p.servicePlanOwned(ctx, w)
	if err != nil || !plan.Service.ShouldRun || plan.Service.Retiring.ActiveEntries == 0 || p.store.first || p.store.priorService == nil {
		return nil, loadbalancestream.ErrService
	}
	prior := p.store.priorService
	if prior.current(ctx) != nil || len(prior.Processes) != 2 || prior.plan.Current.SHA256 != seed.BeforeRuntimeSHA256 ||
		verifyLoadBalanceStreamConfigurationMarkers(ctx, prior, seed.Before) != nil {
		return nil, loadbalancestream.ErrService
	}
	master := (*loadBalanceStreamProcessWitness)(nil)
	for _, process := range prior.Processes {
		if process.PID == prior.MainPID {
			master = process
		}
	}
	if master == nil || !master.current(w.gate.installed.engine, prior.AccountUID, prior.AccountGID) {
		return nil, loadbalancestream.ErrService
	}
	generation, err := captureWAFReloadGeneration(ctx, "/proc", w.gate.installed.engine.binary.path, prior.MainPID)
	if err != nil || len(generation.Workers) != 1 || generation.Master.Start != master.StartTime {
		return nil, loadbalancestream.ErrService
	}
	for _, process := range prior.Processes {
		if process.PID != prior.MainPID && (generation.Workers[0].PID != process.PID || generation.Workers[0].Start != process.StartTime) {
			return nil, loadbalancestream.ErrService
		}
	}
	owned, err := observeLoadBalanceStreamOwnedListeners(ctx, prior, seed.Before)
	if err != nil || len(owned) != len(generation.Listeners) {
		return nil, loadbalancestream.ErrService
	}
	for _, inode := range owned {
		if !generation.Listeners[inode] {
			return nil, loadbalancestream.ErrService
		}
	}
	memoryRaw, err := readLoadBalanceStreamCgroupFile(prior.cgroup, "memory.current", 128)
	memory, e2 := strconv.ParseInt(strings.TrimSuffix(string(memoryRaw), "\n"), 10, 64)
	if err != nil || e2 != nil || memory < 0 || string(memoryRaw) != strconv.FormatInt(memory, 10)+"\n" || memory > plan.Service.MemoryHighBytes {
		return nil, loadbalancestream.ErrService
	}
	if _, _, err := p.servicePlanOwned(ctx, w); err != nil || prior.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	p.serviceIssued = true
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := programQueueCommand(bounded, "/usr/bin/systemctl", plan.Policy...); err != nil {
		return nil, loadbalancestream.ErrService
	}
	// Verify THIS original cgroup/manager invocation under the new exact
	// resources/IP list BEFORE signalling. Policy metadata is not BPF semantics.
	policy, err := observeLoadBalanceStreamService(bounded, w.gate.installed, plan.Service, false)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	same := streamReloadSameOriginalService(prior, policy)
	policy.close()
	if !same || !master.current(w.gate.installed.engine, prior.AccountUID, prior.AccountGID) {
		return nil, loadbalancestream.ErrService
	}
	if _, _, err := p.servicePlanOwned(bounded, w); err != nil {
		return nil, loadbalancestream.ErrService
	}
	if err := unix.PidfdSendSignal(master.pidfd, unix.SIGHUP, nil, 0); err != nil {
		return nil, loadbalancestream.ErrService
	}
	for {
		if bounded.Err() != nil || !master.current(w.gate.installed.engine, prior.AccountUID, prior.AccountGID) {
			return nil, loadbalancestream.ErrService
		}
		if _, _, err := p.servicePlanOwned(bounded, w); err != nil {
			return nil, loadbalancestream.ErrService
		}
		drained, err := generation.drained(bounded)
		if err != nil {
			return nil, loadbalancestream.ErrService
		}
		if drained {
			next, err := observeLoadBalanceStreamService(bounded, w.gate.installed, plan.Service, true)
			if err == nil {
				if !streamReloadSameOriginalService(prior, next) {
					next.close()
					return nil, loadbalancestream.ErrService
				}
				if streamReloadHasOneNewWorker(prior, next) && verifyLoadBalanceStreamConfigurationMarkers(bounded, next, seed.After) == nil {
					closed, err := generation.drained(bounded)
					if closed && err == nil {
						if _, _, err := p.servicePlanOwned(bounded, w); err == nil && next.current(bounded) == nil {
							return next, nil
						}
					}
				}
				next.close()
			}
		}
		select {
		case <-bounded.Done():
			return nil, loadbalancestream.ErrService
		case <-time.After(50 * time.Millisecond):
		}
	}
}
