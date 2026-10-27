//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Original in-memory creator only; no constructor accepts a saved case/PID,
// renderer, shell, unit name, installation ID or a browser-provided binding.
type loadBalanceStreamTrafficController struct {
	owner          *loadBalanceStreamControlOwner
	source         *loadBalanceStreamCoreAuthority
	installed      *loadBalanceStreamInstalledContext
	lifetime       *memcachedUnixRuntimeLease
	mutation       *loadBalanceStreamMutationLease
	store          *loadBalanceStreamConfigurationStore
	journal        *loadBalanceStreamJournal
	config         *loadBalanceStreamConfigurationPublication
	running        *loadBalanceStreamServiceObservation
	stopped        *loadBalanceStreamStoppedObservation
	generationRaw  []byte
	effectsStarted bool
}

func (c *loadBalanceStreamTrafficController) close() {
	if c == nil {
		return
	}
	if c.running != nil {
		c.running.close()
	}
	if c.config != nil {
		c.config.close()
	}
	if c.owner != nil && c.owner.gate != nil {
		c.owner.gate.close()
	}
	if c.journal != nil {
		c.journal.close()
	}
	if c.store != nil {
		c.store.close()
	}
	if c.installed != nil {
		c.installed.close()
	}
	if c.mutation != nil {
		c.mutation.close()
	}
	if c.lifetime != nil {
		c.lifetime.Close()
	}
	if c.source != nil {
		c.source.close()
	}
}

func prepareLoadBalanceStreamTrafficController(ctx context.Context, service *Service, op loadbalancestream.Operation) (*loadBalanceStreamTrafficController, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || service.Config.SystemRoot != "/" ||
		service.Config.SecurityDir != "/etc/panel/security-apps" || os.Geteuid() != 0 ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	if _, err := loadbalancestream.OperationBytes(op); err != nil {
		return nil, err
	}
	c := &loadBalanceStreamTrafficController{}
	fail := func() (*loadBalanceStreamTrafficController, error) {
		c.close()
		return nil, errLoadBalanceStreamInstallationGate
	}
	var err error
	c.source, err = openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return fail()
	}
	grant, err := c.source.controlAuthority(ctx, op)
	if err != nil {
		return fail()
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	c.lifetime, err = acquireMemcachedUnixRuntime(bounded)
	cancel()
	if err != nil {
		return fail()
	}
	bounded, cancel = context.WithTimeout(ctx, 3*time.Second)
	c.mutation, err = acquireLoadBalanceStreamMutation(bounded)
	cancel()
	if err != nil {
		return fail()
	}
	c.installed, err = holdLoadBalanceStreamInstalledContext(ctx)
	if err != nil {
		return fail()
	}
	c.store, err = holdLoadBalanceStreamConfigurationStore(ctx, c.installed, c.source, c.lifetime, c.mutation, grant)
	if err != nil {
		return fail()
	}
	facts, before, probe, kernelSHA, err := c.store.prepareKernel(ctx)
	if err != nil {
		return c.refuseBeforeEffects(ctx, service, op, grant, "kernel-preflight")
	}
	prior, err := loadbalancestream.RenderRuntime(before, loadbalancestream.ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		return fail()
	}
	binding := loadbalancestream.OperationBinding{Format: 1, AppID: "load-balance", AppVersion: loadbalancestream.AppVersion,
		OperationSHA256: grant.OperationSHA256, ManifestSHA256: grant.ManifestSHA256,
		InstalledSHA256: core.Hash(string(c.installed.installed.raw)), ProgrammeInputs: loadBalanceStreamCompiledProgrammeInputsSHA256,
		ActorObservationSHA: grant.ActorObservationSHA256, OriginalConfigSHA256: prior.SHA256}
	binding.OriginalRequestSHA256 = grant.OriginalRequestSHA256
	var seed loadbalancestream.ControlSeed
	if c.store.priorColdBoot != nil {
		if c.store.priorColdBoot.current(ctx, c.store) != nil {
			return fail()
		}
		seed, _, err = loadbalancestream.PrepareColdBootControlSeed(op, binding, before, probe, kernelSHA, facts, c.store.priorColdBoot.record)
	} else {
		seed, _, err = loadbalancestream.PrepareControlSeed(op, binding, before, probe, kernelSHA, facts)
	}
	if err != nil {
		return c.refuseBeforeEffects(ctx, service, op, grant, "control-preflight")
	}
	if c.source.check(ctx, op, binding) != nil || c.store.beforeCurrent(ctx) != nil {
		return fail()
	}
	raw, err := loadbalancestream.ControlSeedBytes(seed)
	if err != nil {
		return fail()
	}
	// From this point even a failed exclusive creation can have left an
	// original directory/file. It can never be relabelled a preflight refusal.
	c.effectsStarted = true
	if _, err := os.Lstat(loadBalanceStreamJobsRoot); errors.Is(err, os.ErrNotExist) {
		if !c.store.first || len(c.store.closed) != 0 {
			return fail()
		}
		root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamJobsRoot, true)
		if err != nil {
			return fail()
		}
		root.Close()
	} else if err != nil {
		return fail()
	}
	c.journal, err = createLoadBalanceStreamJournalAt(ctx, loadBalanceStreamJobsRoot, raw)
	if err != nil {
		return fail()
	}
	gate, err := bindLoadBalanceStreamControlGate(ctx, c.journal, c.installed, c.source)
	if err != nil {
		return fail()
	}
	c.owner, err = bindLoadBalanceStreamControlOwner(ctx, gate, c.lifetime, c.mutation)
	if err != nil {
		gate.close()
		return fail()
	}
	// The fixed actual long-lived executor, not a child with enlarged caps.
	c.owner.service = service
	if c.owner.current(ctx) != nil {
		return fail()
	}
	return c, nil
}

func (c *loadBalanceStreamTrafficController) advance(ctx context.Context, evidence loadbalancestream.ControlAdvanceEvidence) error {
	if c == nil || c.owner == nil || c.owner.current(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	return c.journal.appendOriginal(ctx, evidence)
}

// Fresh read-only runtime observation permits only the original recorded
// retiring worker to disappear. A changed master/current worker, OOM counter,
// cgroup/invocation or unknown third worker is never adopted as success.
func (c *loadBalanceStreamTrafficController) runtimeCurrent(ctx context.Context) error {
	if c == nil || c.config == nil || !c.config.metadataCurrent() || len(c.config.serviceReceipt) == 0 {
		return loadbalancestream.ErrService
	}
	receipt, err := decodeStreamServiceReceipt(c.config.serviceReceipt, c.config.seed)
	if err != nil || c.installed == nil || receipt.InstallationID != c.installed.receipt.InstallationID ||
		c.store == nil || c.config.store != c.store || !c.config.receiptEgressCurrent(ctx, receipt.State) ||
		!reflect.DeepEqual(receipt.Egress, c.store.egress.receipt) {
		return loadbalancestream.ErrService
	}
	if _, err := checkStreamConfigurationPublication(c.config.publication, c.config.original.root, c.config.seed, c.installed.identity.GID, true); err != nil {
		return loadbalancestream.ErrService
	}
	if c.running != nil {
		var master *loadBalanceStreamProcessWitness
		for _, p := range c.running.Processes {
			if p.PID == c.running.MainPID {
				master = p
			}
		}
		if master == nil || !master.current(c.installed.engine, c.installed.identity.UID, c.installed.identity.GID) {
			return loadbalancestream.ErrService
		}
		live, err := observeLoadBalanceStreamService(ctx, c.installed, c.running.plan, true)
		if err != nil {
			return loadbalancestream.ErrService
		}
		defer live.close()
		if !streamReloadSameOriginalService(c.running, live) || !streamServiceMatchesRecorded(live, receipt) ||
			verifyLoadBalanceStreamConfigurationMarkers(ctx, live, mustStreamReceiptEntries(c.config.seed)) != nil {
			return loadbalancestream.ErrService
		}
		return nil
	}
	if c.stopped == nil || receipt.State != "stopped" || !c.stopped.ManagerCleanupObserved ||
		!c.stopped.originalProcessesExited() || !streamManagedServiceInactive(ctx, c.stopped.InvocationID) {
		return loadbalancestream.ErrService
	}
	return nil
}

func mustStreamReceiptEntries(raw []byte) []loadbalancestream.Entry {
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		return nil
	}
	return seed.After
}

func (c *loadBalanceStreamTrafficController) publishGeneration(ctx context.Context) ([]byte, error) {
	if c == nil || c.owner == nil || c.owner.current(ctx) != nil || c.runtimeCurrent(ctx) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	seed, records, chain, err := c.journal.original(ctx)
	if err != nil || len(records) != 11 || chain.Complete || !bytes.Equal(seed, c.config.seed) {
		return nil, loadbalancestream.ErrGeneration
	}
	for _, path := range []string{loadBalanceStreamStateRoot, loadBalanceStreamGenerationPublicationsRoot} {
		_, err := os.Lstat(path)
		if c.store.first {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, loadbalancestream.ErrGeneration
			}
			root, err := openLoadBalanceStreamFixedRoot(path, true)
			if err != nil {
				return nil, loadbalancestream.ErrGeneration
			}
			root.Close()
		} else if err != nil {
			return nil, loadbalancestream.ErrGeneration
		}
	}
	state, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamStateRoot, false)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	defer state.Close()
	original, err := holdStreamGenerationFileAt(state, func() bool { return streamInstalledFixedRootCurrent(state, loadBalanceStreamStateRoot) })
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	defer original.close()
	if original.missing != c.store.first || !original.missing && (c.store.generation == nil || !bytes.Equal(original.raw, c.store.generation.raw)) {
		return nil, loadbalancestream.ErrGeneration
	}
	pool, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamGenerationPublicationsRoot, false)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	defer pool.Close()
	if streamConfigurationExactDirectories(pool, c.store.closed) != nil || len(c.store.closed) >= 128 ||
		c.owner.current(ctx) != nil || c.runtimeCurrent(ctx) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	id := c.store.original.RequestID
	if createStreamRootPrivateDirectory(pool, id) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	pub, err := pool.OpenRoot(id)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	defer pub.Close()
	before, err := pub.Stat(".")
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	anchor := func() bool {
		a, e1 := pub.Stat(".")
		b, e2 := pool.Lstat(id)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(a) && memcachedUnixAdminDirectoryInfo(b) &&
			os.SameFile(before, a) && os.SameFile(a, b) && streamInstalledFixedRootCurrent(pool, loadBalanceStreamGenerationPublicationsRoot)
	}
	authorize := func(ctx context.Context) error {
		if _, err := c.owner.configurationPhase(ctx, "service-observed"); err != nil || !anchor() || c.runtimeCurrent(ctx) != nil {
			return loadbalancestream.ErrGeneration
		}
		return nil
	}
	p, err := prepareStreamGenerationPublicationAt(ctx, pub, anchor, original, c.installed.receipt.InstallationID, seed, records, authorize)
	if err != nil || p.publish(ctx, authorize) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	current, err := holdStreamGenerationFileAt(state, func() bool { return streamInstalledFixedRootCurrent(state, loadBalanceStreamStateRoot) })
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	defer current.close()
	if current.missing || !bytes.Equal(current.raw, p.proposal) || c.runtimeCurrent(ctx) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	if _, err := checkStreamGenerationPublication(pub, seed, current.raw); err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	return bytes.Clone(current.raw), nil
}

// Original synchronous body, run once by the tracked background submission.
// Stages remain durable before every effect; every error retains the exact
// original bytes/unknown state with no traffic retry or automatic rollback.
func (c *loadBalanceStreamTrafficController) execute(ctx context.Context) (core.LoadBalanceStreamNativeResult, error) {
	var empty core.LoadBalanceStreamNativeResult
	if c == nil || c.owner == nil || c.owner.current(ctx) != nil {
		return empty, errLoadBalanceStreamInstallationGate
	}
	if c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil ||
		c.installed.current(ctx) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{AccountReceiptSHA256: c.installed.accountSHA}) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil {
		return empty, errLoadBalanceStreamInstallationGate
	}
	var err error
	c.config, err = c.store.stage(ctx, c.owner)
	if err != nil {
		return empty, err
	}
	if c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil ||
		c.config.verifySyntaxOwned(ctx, c.owner) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	if _, err := c.config.promoteOwned(ctx, c.owner); err != nil {
		return empty, err
	}
	if c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil ||
		c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	_, plan, err := c.config.servicePlanOwned(ctx, c.owner)
	if err != nil {
		return empty, err
	}
	if c.config.applyEgressOwned(ctx, c.owner) != nil {
		return empty, loadbalancestream.ErrEgressGuard
	}
	switch {
	case !plan.Service.ShouldRun:
		c.stopped, err = c.config.stopOwned(ctx, c.owner)
	case plan.Service.Retiring.ActiveEntries == 0:
		c.running, err = c.config.startOwnedInitial(ctx, c.owner)
	default:
		c.running, err = c.config.reloadOwned(ctx, c.owner)
	}
	if err != nil {
		return empty, err
	}
	if c.stopped != nil && c.config.retireStoppedEgressOwned(ctx, c.owner, c.stopped) != nil {
		return empty, loadbalancestream.ErrEgressGuard
	}
	digest, err := c.config.retainServiceOwned(ctx, c.owner, c.running, c.stopped)
	if err != nil || c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{ServiceObservationSHA: digest}) != nil {
		return empty, loadbalancestream.ErrService
	}
	generation, err := c.publishGeneration(ctx)
	if err != nil {
		return empty, err
	}
	c.generationRaw = bytes.Clone(generation)
	if c.advance(ctx, loadbalancestream.ControlAdvanceEvidence{}) != nil {
		return empty, loadbalancestream.ErrJournal
	}
	seed, records, chain, err := c.journal.original(ctx)
	g, e2 := loadbalancestream.DecodeGenerationRecord(generation)
	if err != nil || e2 != nil || !chain.Complete || !loadbalancestream.GenerationRecordBindsOriginal(generation, c.installed.receipt.InstallationID, g.Generation, seed, records) {
		return empty, loadbalancestream.ErrGeneration
	}
	op, err := loadbalancestream.DecodeControlSeed(seed)
	if err != nil {
		return empty, err
	}
	result := core.LoadBalanceStreamNativeResult{Format: 1, RequestID: op.Operation.RequestID, Version: loadbalancestream.AppVersion,
		OperationSHA256: loadbalancestream.OperationSHA256(op.Operation), State: "committed", Seed: string(seed),
		Generation: g.Generation, GenerationSHA256: core.Hash(string(generation)), ServiceReceiptSHA256: digest}
	for _, record := range records {
		result.Records = append(result.Records, string(record))
	}
	if core.ValidateLoadBalanceStreamNativeResult(result, op.Operation) != nil {
		return empty, loadbalancestream.ErrJournal
	}
	if err := c.retainOriginalCompletion(ctx, result); err != nil {
		return empty, err
	}
	return result, nil
}

// Metadata only after the final journal append. This cannot grant another
// signal/start/reload: all effect methods still require their earlier phase.
func (c *loadBalanceStreamTrafficController) completedCreatorCurrent(ctx context.Context) error {
	if c == nil || c.owner == nil || c.journal == nil || !c.journal.creator || c.journal.unknown ||
		c.owner.process == nil || c.owner.process.PID != os.Getpid() || !c.journal.current() ||
		!c.lifetime.current() || !c.mutation.current() || !streamControlHeldLease(c.journal.lock, true) ||
		!streamControlHeldLease(c.lifetime.file.file, false) || !streamControlHeldLease(c.mutation.file, true) ||
		c.installed.current(ctx) != nil || c.runtimeCurrent(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	raw, _, chain, err := c.journal.original(ctx)
	if err != nil || !chain.Complete || !bytes.Equal(raw, c.owner.gate.seed) ||
		c.owner.service.authorizeModuleCandidate(ctx, filepath.Join(c.journal.path, "run.lock"), c.owner.process) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	state, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamStateRoot, false)
	if err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	defer state.Close()
	current, err := holdStreamGenerationFileAt(state, func() bool { return streamInstalledFixedRootCurrent(state, loadBalanceStreamStateRoot) })
	if err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	defer current.close()
	if current.missing || len(c.generationRaw) == 0 || !bytes.Equal(current.raw, c.generationRaw) || !current.current() {
		return errLoadBalanceStreamInstallationGate
	}
	actual, err := c.source.controlAuthority(ctx, seed.Operation)
	if err != nil || actual != c.owner.gate.original {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

func (c *loadBalanceStreamTrafficController) retainOriginalCompletion(ctx context.Context, result core.LoadBalanceStreamNativeResult) error {
	if c == nil || c.config == nil || c.config.completionIssued || c.completedCreatorCurrent(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) == 0 || len(raw) >= core.LoadBalanceStreamNativeResultMaxBytes {
		return loadbalancestream.ErrJournal
	}
	raw = append(raw, '\n')
	c.config.completionIssued = true
	c.config.completionReceipt = bytes.Clone(raw)
	if writeStreamControlCompletion(c.config.publication, raw) != nil || !c.config.metadataCurrent() ||
		c.completedCreatorCurrent(ctx) != nil {
		return loadbalancestream.ErrJournal
	}
	return nil
}
