//go:build linux

package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

func holdLoadBalanceStreamProcess(pid int, installed *loadBalanceStreamInstalledContext) (*loadBalanceStreamProcessWitness, error) {
	if pid < 2 || pid > 1<<30 || installed == nil || installed.engine == nil {
		return nil, loadbalancestream.ErrService
	}
	p := &loadBalanceStreamProcessWitness{PID: pid, pidfd: -1}
	fail := func() (*loadBalanceStreamProcessWitness, error) { p.close(); return nil, loadbalancestream.ErrService }
	var err error
	p.pidfd, err = unix.PidfdOpen(pid, 0)
	if err != nil {
		return fail()
	}
	p.proc, err = os.OpenRoot(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return fail()
	}
	p.before, err = p.proc.Stat(".")
	if err != nil || !p.current(installed.engine, installed.identity.UID, installed.identity.GID) {
		return fail()
	}
	return p, nil
}

// This caller supplies ACTUAL freshly measured resources. The fixed pure
// launch plan is regenerated and bound to the original seed, not supplied as
// an argv/property/hash claim by a request or a saved old controller.
func (p *loadBalanceStreamConfigurationPublication) activationPlan(ctx context.Context, w *loadBalanceStreamControlOwner) (loadbalancestream.ControlSeed, loadbalancestream.ServiceLaunchPlan, error) {
	if p == nil || !p.promoted || !p.syntaxIssued || !p.syntaxVerified || p.original == nil || p.publication == nil || !p.metadataCurrent() {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	raw, err := w.configurationPhase(ctx, "service-intent")
	if err != nil || !bytes.Equal(raw, p.seed) || p.original.root.Name() != loadBalanceStreamConfigurationRoot || p.publication.Name() != filepath.Join(loadBalanceStreamConfigurationPublicationsRoot, p.request) {
		return loadbalancestream.ControlSeed{}, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		return seed, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	if _, err := checkStreamConfigurationPublication(p.publication, p.original.root, raw, w.gate.installed.identity.GID, true); err != nil {
		return seed, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, w.gate.installed)
	if err != nil {
		return seed, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return seed, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	facts.Validation.PanelControlPorts = ports
	plan, err := loadbalancestream.PlanControlServiceLaunch(seed, facts, p.request)
	if err != nil || !bytes.Equal(plan.Service.Current.Main, p.proposal) {
		return seed, loadbalancestream.ServiceLaunchPlan{}, loadbalancestream.ErrService
	}
	return seed, plan, nil
}

// INITIAL creation only; running/reload/drain/stop remain separate original
// paths. The returned evidence proves actual owned processes/resources and
// configuration markers, NOT upstream health or real TCP/UDP forwarding. Those
// require independent native traffic tests and honest UI states before release.
func (p *loadBalanceStreamConfigurationPublication) startOwnedInitial(ctx context.Context, w *loadBalanceStreamControlOwner) (*loadBalanceStreamServiceObservation, error) {
	if p == nil || p.serviceIssued || !p.serviceEgressCurrent(ctx) {
		return nil, fmt.Errorf("initial current original metadata: %w", loadbalancestream.ErrService)
	}
	seed, plan, err := p.servicePlanOwned(ctx, w)
	if err != nil || !plan.Service.ShouldRun || plan.Service.Retiring.ActiveEntries != 0 || !p.store.first && !p.store.priorStopped && p.store.priorColdBoot == nil {
		return nil, fmt.Errorf("initial original plan and retiring admission: %w", loadbalancestream.ErrService)
	}
	prior, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
	if err != nil || prior["LoadState"] != "not-found" || prior["ActiveState"] != "inactive" || prior["SubState"] != "dead" || prior["MainPID"] != "0" || prior["ControlPID"] != "0" || prior["InvocationID"] != "" {
		return nil, fmt.Errorf("initial fixed unit absence: %w", loadbalancestream.ErrService)
	}
	census, err := observeLoadBalanceStreamHostSockets(ctx)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	// Keep every observed live/unknown socket blocking. A canonical ownerless
	// TCP TIME_WAIT row from a closed probe is not a live socket. Actual native
	// bind and owned-listener verification remain mandatory, with no retry or
	// success fallback if another process wins the port after this read.
	for _, socket := range census.sockets {
		if streamInitialSocketConflicts(socket, seed.After) {
			census.close()
			return nil, fmt.Errorf("initial observed occupied target: %w", loadbalancestream.ErrService)
		}
	}
	if !census.current() {
		census.close()
		return nil, loadbalancestream.ErrService
	}
	census.close()
	if _, err := w.configurationPhase(ctx, "service-intent"); err != nil {
		return nil, loadbalancestream.ErrService
	}
	if _, err := checkStreamConfigurationPublication(p.publication, p.original.root, p.seed, w.gate.installed.identity.GID, true); err != nil || !p.metadataCurrent() {
		return nil, loadbalancestream.ErrService
	}
	if p.store.priorColdBoot != nil && p.store.priorColdBoot.current(ctx, p.store) != nil {
		return nil, loadbalancestream.ErrService
	}
	p.serviceIssued = true
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if _, err := programQueueCommand(bounded, "/usr/bin/systemd-run", plan.Start...); err != nil {
		return nil, loadbalancestream.ErrService
	}
	// Pin THIS start's manager invocation and actual master pidfd immediately.
	// A later matching process/unit name cannot stand in for an exited attempt.
	main, invocation, err := streamServiceManagerFacts(bounded)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	master, err := holdLoadBalanceStreamProcess(main, w.gate.installed)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	defer master.close()
	for {
		if bounded.Err() != nil || !master.current(w.gate.installed.engine, w.gate.installed.identity.UID, w.gate.installed.identity.GID) {
			return nil, loadbalancestream.ErrService
		}
		if _, err := w.configurationPhase(bounded, "service-intent"); err != nil {
			return nil, loadbalancestream.ErrService
		}
		service, err := observeLoadBalanceStreamService(bounded, w.gate.installed, plan.Service, false)
		if err == nil {
			if service.MainPID != main || service.InvocationID != invocation {
				service.close()
				return nil, loadbalancestream.ErrService
			}
			if service.MemoryEvents.OOM != 0 || service.MemoryEvents.Kills != 0 || service.MemoryEvents.GroupKills != 0 {
				service.close()
				return nil, loadbalancestream.ErrService
			}
			if verifyLoadBalanceStreamConfigurationMarkers(bounded, service, seed.After) == nil {
				if _, err := w.configurationPhase(bounded, "service-intent"); err != nil || !master.current(w.gate.installed.engine, service.AccountUID, service.AccountGID) {
					service.close()
					return nil, loadbalancestream.ErrService
				}
				if _, err := checkStreamConfigurationPublication(p.publication, p.original.root, p.seed, service.AccountGID, true); err != nil || !p.metadataCurrent() {
					service.close()
					return nil, loadbalancestream.ErrService
				}
				return service, nil
			}
			service.close()
		}
		select {
		case <-bounded.Done():
			return nil, loadbalancestream.ErrService
		case <-time.After(50 * time.Millisecond):
		}
	}
}
