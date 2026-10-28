//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamInstallController struct {
	submission *loadBalanceStreamHeldSubmission
	source     *loadBalanceStreamCoreAuthority
	lifetime   *memcachedUnixRuntimeLease
	mutation   *loadBalanceStreamMutationLease
	engine     *loadBalanceStreamHeldEngine
	gate       *loadBalanceStreamInstallationGate
	grant      core.LoadBalanceStreamInstallAuthority
}

// Effect authority belongs only to this new original parent, never to a
// directory opener, version label, recovered old journal or supplied hash.
func (w *loadBalanceStreamInstallController) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || w.gate == nil || w.gate.current(ctx) != nil || w.submission == nil || !w.submission.current() || w.source == nil || w.lifetime == nil || !w.lifetime.current() || w.mutation == nil || !w.mutation.current() || w.engine == nil || !w.engine.current() || checkLoadBalanceStreamInstallParentKernel(ctx, w.submission.value.JobID) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

func (w *loadBalanceStreamInstallController) quiescent(ctx context.Context) error {
	if w.current(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if err := w.checkQueues(ctx); err != nil {
		return err
	}
	return w.current(ctx)
}

func (w *loadBalanceStreamInstallController) checkQueues(ctx context.Context) error {
	if w == nil {
		return errLoadBalanceStreamInstallationGate
	}
	owner := &loadBalanceStreamUpgradeOwner{source: w.source, original: w.grant, lifetime: w.lifetime, mutation: w.mutation, parent: w}
	if err := observeLoadBalanceStreamLegacyQueues(ctx, owner.current); err != nil {
		return err
	}
	return checkLoadBalanceStreamUpgrade(ctx, owner)
}

func ensureLoadBalanceStreamModuleDirectory(ctx context.Context, authorize func(context.Context) error) (*modulePrivateDirectory, error) {
	s := New(Config{})
	if ctx == nil || ctx.Err() != nil || authorize == nil || authorize(ctx) != nil || threatIDSTrustedParents(s.Config.SecurityDir, false) != nil {
		return nil, errLoadBalanceStreamModule
	}
	root, err := s.softwareManifestDirectory()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	current := root
	var children []*os.Root
	defer func() {
		for i := len(children) - 1; i >= 0; i-- {
			children[i].Close()
		}
	}()
	for _, name := range []string{"modules", "load-balance"} {
		if authorize(ctx) != nil {
			return nil, errLoadBalanceStreamModule
		}
		if _, err := current.Lstat(name); errors.Is(err, os.ErrNotExist) {
			if current.Mkdir(name, 0700) != nil || ruleFeedStoreSync(current) != nil {
				return nil, errLoadBalanceStreamModule
			}
		} else if err != nil {
			return nil, errLoadBalanceStreamModule
		}
		info, err := current.Lstat(name)
		if err != nil || !moduleRecordInfo(info, true, false) {
			return nil, errLoadBalanceStreamModule
		}
		child, err := current.OpenRoot(name)
		if err != nil {
			return nil, errLoadBalanceStreamModule
		}
		children = append(children, child)
		held, err := child.Stat(".")
		if err != nil || !geoStoreStableInfo(info, held) {
			return nil, errLoadBalanceStreamModule
		}
		current = child
	}
	if authorize(ctx) != nil {
		return nil, errLoadBalanceStreamModule
	}
	return s.moduleRecordDirectory("load-balance")
}

func streamInstallUnitProperties(ctx context.Context, unit string) (map[string]string, error) {
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,ExecMainStatus,Result,InvocationID")
	if err != nil || len(raw) > 4096 || !strings.HasSuffix(raw, "\n") {
		return nil, errLoadBalanceStreamAccount
	}
	want := map[string]bool{"LoadState": true, "ActiveState": true, "SubState": true, "MainPID": true, "ControlPID": true, "ExecMainStatus": true, "Result": true, "InvocationID": true}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !want[key] {
			return nil, errLoadBalanceStreamAccount
		}
		if _, exists := out[key]; exists {
			return nil, errLoadBalanceStreamAccount
		}
		out[key] = value
	}
	if len(out) != len(want) {
		return nil, errLoadBalanceStreamAccount
	}
	return out, nil
}

// Only this currently authorized original parent may initialize the normal
// coordination inode on a fresh installation. The account child's namespace
// opens that same inode read-only and must never create or repair it. Release
// this separate lease before starting the child so its exclusive lock can run.
func (w *loadBalanceStreamInstallController) prepareAccountCoordination(ctx context.Context) error {
	if w.quiescent(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	lease, err := productionDockerMutationStore().acquire(bounded)
	cancel()
	if err != nil {
		return err
	}
	defer lease.Close()
	return lease.use(ctx, w.quiescent)
}

// Exactly one start-and-wait command follows the already durable account intent and
// original parent permit. A missing reply/timeout/failure never starts, resets,
// stops or adopts the dependency again. Parent holds NO Compose lease here.
func (w *loadBalanceStreamInstallController) accountChild(ctx context.Context) error {
	if w.quiescent(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	unit, err := loadbalancestream.AccountCreationUnit(w.submission.value.JobID)
	if err != nil {
		return err
	}
	prior, err := streamInstallUnitProperties(ctx, unit)
	if err != nil || prior["LoadState"] != "loaded" || prior["ActiveState"] != "inactive" || prior["SubState"] != "dead" || prior["MainPID"] != "0" || prior["ControlPID"] != "0" || prior["InvocationID"] != "" {
		return errLoadBalanceStreamAccount
	}
	if err = w.prepareAccountCoordination(ctx); err != nil {
		return err
	}
	if _, err = writeLoadBalanceStreamAccountPermit(ctx, w.gate); err != nil {
		return err
	}
	if w.quiescent(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	// --wait holds the manager reference until this new invocation terminates.
	// A plain --no-block followed by inactive/dead can see the pre-start state
	// and incorrectly count an old success before the new child has run.
	bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
	_, err = programQueueCommand(bounded, "/usr/bin/systemctl", "--wait", "start", unit)
	cancel()
	if err != nil {
		return streamInstallPhaseError("专用身份完成等待", err)
	}
	state, err := streamInstallUnitProperties(ctx, unit)
	if err != nil || !streamInstallAccountChildTerminated(state) {
		return streamInstallPhaseError("专用身份完成状态", errLoadBalanceStreamAccount)
	}
	return w.current(ctx)
}

// An observation after the original successful --wait, never start authority.
// systemd may garbage-collect a successfully terminated unit before show loads
// its static template again, losing InvocationID and other runtime statistics.
// The caller still requires its original live grant, complete owned account
// receipt and fresh NSS, then the durable installation journal before commit.
func streamInstallAccountChildTerminated(state map[string]string) bool {
	if len(state) != 8 || state["LoadState"] != "loaded" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["MainPID"] != "0" || state["ControlPID"] != "0" || state["ExecMainStatus"] != "0" || state["Result"] != "success" {
		return false
	}
	id, present := state["InvocationID"]
	return present && (id == "" || core.ValidID(id) && id != strings.Repeat("0", 32))
}

// Fixed original parent only. Availability remains false until the separate
// runtime/control/recovery/UI lifecycle is complete. In particular the offline
// signature verifier below cannot authorize this through today's HTTP-only
// signed package, an ordinary unbound build or a manually named job/CLI.
func RunLoadBalanceStreamInstallJob(job string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	if checkLoadBalanceStreamInstallParentKernel(ctx, job) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	submission, err := holdLoadBalanceStreamSubmission(job)
	if err != nil {
		return err
	}
	defer submission.close()
	source, err := openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return err
	}
	defer source.close()
	grant, err := source.installAuthority(ctx, job)
	if err != nil {
		return err
	}
	authority, err := appcatalog.VerifyLoadBalanceStreamReleaseEnvelope(ctx, submission.value.Release, grant.AppVersion, grant.ManifestSHA256)
	if err != nil || !authority.Matches(grant.AppVersion, grant.ManifestSHA256) {
		return errLoadBalanceStreamInstallationGate
	}
	bounded, stop := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(bounded)
	stop()
	if err != nil {
		return err
	}
	defer lifetime.Close()
	bounded, stop = context.WithTimeout(ctx, 3*time.Second)
	mutation, err := acquireLoadBalanceStreamMutation(bounded)
	stop()
	if err != nil {
		return err
	}
	defer mutation.close()
	w := &loadBalanceStreamInstallController{submission: submission, source: source, lifetime: lifetime, mutation: mutation, grant: grant}
	if source.checkInstall(ctx, grant) != nil || !submission.current() || w.checkQueues(ctx) != nil || checkLoadBalanceStreamInstallParentKernel(ctx, job) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	engine, err := holdLoadBalanceStreamEngine(ctx)
	if err != nil {
		return err
	}
	defer engine.close()
	w.engine = engine
	if raw, err := streamAccountParentProc("/proc/meminfo", 65536); err != nil || loadBalanceStreamInstallMemoryAdmission(raw) != nil {
		return loadbalancestream.ErrService
	}
	s := New(Config{})
	module, err := s.moduleRecordDirectory("load-balance")
	var original *loadBalanceStreamHeldModule
	if err == nil {
		defer module.Close()
		original, err = holdLoadBalanceStreamModuleAt(module.Root, module.current)
		if err != nil {
			return err
		}
		defer original.close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var old []byte
	oldVersion := ""
	if original != nil && !original.missing {
		old = original.raw
		record, err := decodeLoadBalanceStreamModule(old)
		if err != nil {
			return err
		}
		oldVersion, _ = record["version"].(string)
		// First native migration only. A later native-version migration must
		// preserve its actual generation/installation chain, not reset it.
		if oldVersion != "1.8.4" && oldVersion != "1.8.5" {
			return errLoadBalanceStreamIndependentLifecycle
		}
	}
	if grant.Action == "install" && len(old) != 0 || grant.Action == "update" && len(old) == 0 {
		return errLoadBalanceStreamModule
	}
	empty, err := loadbalancestream.RenderRuntime([]loadbalancestream.Entry{}, loadbalancestream.ServiceRuntimePrefix, loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil {
		return err
	}
	releaseRaw, err := json.Marshal(submission.value.Release)
	if err != nil {
		return err
	}
	seed := loadbalancestream.InstallationSeed{Format: 1, Nonce: core.ID(), JobID: job, ActorID: grant.ActorID, Action: grant.Action, AppVersion: grant.AppVersion, AccessRevision: grant.AccessRevision, ActorObservationSHA256: grant.ActorObservationSHA256, ManifestSHA256: grant.ManifestSHA256, PayloadSHA256: grant.PayloadSHA256, OriginalRequestSHA256: grant.OriginalRequestSHA256, KeySHA256: grant.KeySHA256, JobCreatedAt: grant.JobCreatedAt, CatalogSHA256: authority.CatalogSHA256(), SubmissionSHA256: core.Hash(string(releaseRaw)), ProgrammeInputsSHA256: loadBalanceStreamCompiledProgrammeInputsSHA256, OriginalModuleVersion: oldVersion, EmptyConfigurationSHA: empty.SHA256}
	if len(old) != 0 {
		seed.OriginalModuleSHA256 = core.Hash(string(old))
	}
	seedRaw, err := loadbalancestream.InstallationSeedBytes(seed)
	if err != nil {
		return err
	}
	if source.checkInstall(ctx, grant) != nil || !engine.current() || !submission.current() || !lifetime.current() || !mutation.current() || original != nil && !original.current() {
		return errLoadBalanceStreamInstallationGate
	}
	anchor, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallationJobsRoot, true)
	if err != nil {
		return err
	}
	anchor.Close()
	j, err := createLoadBalanceStreamInstallationJournalAt(ctx, loadBalanceStreamInstallationJobsRoot, seedRaw, releaseRaw)
	if err != nil {
		return err
	}
	defer j.close()
	gate, err := bindLoadBalanceStreamInstallationGate(ctx, j, source)
	if err != nil {
		return err
	}
	w.gate = gate
	if w.quiescent(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if module == nil {
		module, err = ensureLoadBalanceStreamModuleDirectory(ctx, w.current)
		if err != nil {
			return err
		}
		defer module.Close()
		original, err = holdLoadBalanceStreamModuleAt(module.Root, module.current)
		if err != nil {
			return err
		}
		defer original.close()
		if !original.missing {
			return errLoadBalanceStreamModule
		}
	}
	if !original.current() || w.quiescent(ctx) != nil {
		return errLoadBalanceStreamModule
	}
	identityStore, err := openLoadBalanceStreamAccountStoreForCreation()
	if err != nil {
		return err
	}
	identityStore.root.Close()
	if err = j.appendOriginal(ctx, loadbalancestream.InstallationEvidence{}); err != nil {
		return err
	}
	if err = w.accountChild(ctx); err != nil {
		return err
	}
	identity, accountSHA, err := loadBalanceStreamAccountReceiptHash(ctx)
	if err != nil || w.quiescent(ctx) != nil || !original.current() {
		return errLoadBalanceStreamAccount
	}
	if err = j.appendOriginal(ctx, loadbalancestream.InstallationEvidence{AccountReceiptSHA256: accountSHA}); err != nil {
		return err
	}
	// Account child has exited and released its independent Compose lease.
	// Only now may parent serialize the module publication with other native
	// mutations. This lease performs no Docker command or daemon operation.
	bounded, stop = context.WithTimeout(ctx, 3*time.Second)
	engineLease, err := productionDockerMutationStore().acquire(bounded)
	stop()
	if err != nil {
		return err
	}
	defer engineLease.Close()
	return engineLease.use(ctx, func(active context.Context) error {
		authorize := func(c context.Context) error {
			if !engineLease.currentLocked() {
				return errLoadBalanceStreamInstallationGate
			}
			return w.current(c)
		}
		if authorize(active) != nil || w.quiescent(active) != nil || !original.current() {
			return errLoadBalanceStreamInstallationGate
		}
		proposal, err := loadBalanceStreamModuleProposal(seedRaw, original.raw, time.Now().UTC())
		if err != nil {
			return err
		}
		publicationRoot, pubCurrent, err := createLoadBalanceStreamPublicationRoot(active, job)
		if err != nil {
			return err
		}
		defer publicationRoot.Close()
		publication, err := prepareLoadBalanceStreamModulePublicationAt(active, publicationRoot, pubCurrent, original, seedRaw, proposal, authorize)
		if err != nil {
			return err
		}
		defer publication.close()
		if err = j.appendOriginal(active, loadbalancestream.InstallationEvidence{}); err != nil {
			return err
		}
		publishedSHA, err := publication.publish(active, authorize)
		if err != nil {
			return err
		}
		if err = j.appendOriginal(active, loadbalancestream.InstallationEvidence{PublishedModuleSHA256: publishedSHA}); err != nil {
			return err
		}
		_, records, chain, err := j.original(active)
		if err != nil || len(records) != 5 || chain.Complete || authorize(active) != nil {
			return errLoadBalanceStreamInstallationJournal
		}
		final, err := loadbalancestream.NextInstallationEvent(seedRaw, records, loadbalancestream.InstallationEvidence{})
		if err != nil {
			return err
		}
		receipt := loadBalanceStreamInstallationReceipt{Format: 1, InstallationID: seed.Nonce, JobID: job, Version: seed.AppVersion, SeedSHA256: core.Hash(string(seedRaw)), FinalEventSHA256: core.Hash(string(final)), PublishedModuleSHA256: publishedSHA, AccountReceiptSHA256: accountSHA, NSSSHA256: identity.SHA256, ProgrammeInputsSHA256: seed.ProgrammeInputsSHA256, NginxReleaseID: engine.release.ID, NginxSHA256: engine.binary.sha, NginxManifestSHA256: engine.manifest.sha, EmptyConfigurationSHA256: seed.EmptyConfigurationSHA}
		if err = writeStreamInstallationReceipt(active, receipt, authorize); err != nil {
			return err
		}
		if err = j.appendOriginal(active, loadbalancestream.InstallationEvidence{}); err != nil {
			return err
		}
		// Completion is read back from the actual original six-event chain;
		// no caller flag or expected final-event bytes alone can make success.
		_, completed, complete, err := j.original(active)
		if err != nil || !complete.Complete || complete.OriginalUnknown || len(completed) != 6 || !bytes.Equal(completed[5], final) || !engineLease.currentLocked() || !lifetime.current() || !mutation.current() || !submission.current() || !engine.current() || source.checkInstall(active, grant) != nil || checkLoadBalanceStreamInstallParentKernel(active, job) != nil {
			return errLoadBalanceStreamInstallationJournal
		}
		installed, err := holdLoadBalanceStreamModuleAt(module.Root, module.current)
		if err != nil {
			return err
		}
		defer installed.close()
		if !bytes.Equal(installed.raw, proposal) || filepath.Base(j.path) != job {
			return errLoadBalanceStreamModule
		}
		actual, actualSHA, err := loadBalanceStreamAccountReceiptHash(active)
		if err != nil || actual != identity || actualSHA != accountSHA {
			return errLoadBalanceStreamAccount
		}
		return nil
	})
}
