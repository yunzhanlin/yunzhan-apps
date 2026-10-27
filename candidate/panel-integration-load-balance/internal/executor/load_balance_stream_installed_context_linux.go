//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Read-only original installed-instance prerequisite for the separate traffic
// controller. A 1.8 HTTP receipt, supplied installation ID/hash, filesystem
// opener or old install actor never grants a new control operation authority.
// Fresh Core control authority and real runtime/configuration leases remain
// independently mandatory before every effect.
type loadBalanceStreamInstalledContext struct {
	module                              *modulePrivateDirectory
	installed                           *loadBalanceStreamHeldModule
	journal                             *loadBalanceStreamInstallationJournal
	submission                          *loadBalanceStreamHeldSubmission
	receiptRoot                         *os.Root
	observationRoot                     *os.Root
	receiptRaw, observationRaw, seedRaw []byte
	receipt                             loadBalanceStreamInstallationReceipt
	result                              core.LoadBalanceStreamInstallResult
	engine                              *loadBalanceStreamHeldEngine
	identity                            loadBalanceStreamIdentity
	accountSHA                          string
	nss                                 *loadBalanceStreamNSSConfiguration
}

func (w *loadBalanceStreamInstalledContext) close() {
	if w == nil {
		return
	}
	if w.engine != nil {
		w.engine.close()
		w.engine = nil
	}
	if w.nss != nil {
		w.nss.close()
		w.nss = nil
	}
	if w.submission != nil {
		w.submission.close()
		w.submission = nil
	}
	if w.journal != nil {
		w.journal.close()
		w.journal = nil
	}
	if w.installed != nil {
		w.installed.close()
		w.installed = nil
	}
	if w.module != nil {
		w.module.Close()
		w.module = nil
	}
	if w.receiptRoot != nil {
		w.receiptRoot.Close()
		w.receiptRoot = nil
	}
	if w.observationRoot != nil {
		w.observationRoot.Close()
		w.observationRoot = nil
	}
	clear(w.receiptRaw)
	clear(w.observationRaw)
	clear(w.seedRaw)
}

func holdLoadBalanceStreamInstalledContext(ctx context.Context) (*loadBalanceStreamInstalledContext, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	w := &loadBalanceStreamInstalledContext{}
	fail := func() (*loadBalanceStreamInstalledContext, error) {
		w.close()
		return nil, errLoadBalanceStreamInstallationGate
	}
	s := &Service{Config: Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps"}}
	if threatIDSTrustedParents(s.Config.SecurityDir, false) != nil {
		return fail()
	}
	var err error
	w.nss, err = holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return fail()
	}
	w.module, err = s.moduleRecordDirectory("load-balance")
	if err != nil {
		return fail()
	}
	w.installed, err = holdLoadBalanceStreamModuleAt(w.module.Root, w.module.current)
	if err != nil || w.installed.missing {
		return fail()
	}
	v, err := decodeLoadBalanceStreamModule(w.installed.raw)
	if err != nil || v["version"] != loadbalancestream.AppVersion {
		return fail()
	}
	epoch, ok := v["installation_id"].(string)
	if !ok || !core.ValidID(epoch) {
		return fail()
	}
	w.receiptRoot, err = openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallationsRoot, false)
	if err != nil {
		return fail()
	}
	w.receiptRaw, err = streamInstallationPrivateRead(w.receiptRoot, epoch+".json", 8192)
	if err != nil {
		return fail()
	}
	w.receipt, err = decodeStreamInstallationReceipt(w.receiptRaw)
	if err != nil || w.receipt.InstallationID != epoch || w.receipt.PublishedModuleSHA256 != core.Hash(string(w.installed.raw)) {
		return fail()
	}
	w.journal, err = openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, w.receipt.JobID)
	if err != nil {
		return fail()
	}
	w.seedRaw, _, _, err = w.journal.original(ctx)
	if err != nil {
		return fail()
	}
	w.submission, err = holdLoadBalanceStreamSubmission(w.receipt.JobID)
	if err != nil {
		return fail()
	}
	w.observationRoot, err = openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallObservationsRoot, false)
	if err != nil {
		return fail()
	}
	w.observationRaw, err = streamInstallationPrivateRead(w.observationRoot, w.receipt.JobID+".json", 2048)
	if err != nil {
		return fail()
	}
	w.result, err = readLoadBalanceStreamCommittedInstallation(ctx, w.receipt.JobID)
	if err != nil {
		return fail()
	}
	w.engine, err = holdLoadBalanceStreamRecordedEngine(ctx, w.receipt.NginxReleaseID)
	if err != nil {
		return fail()
	}
	w.identity, w.accountSHA, err = loadBalanceStreamAccountReceiptHash(ctx)
	if err != nil {
		return fail()
	}
	if w.current(ctx) != nil {
		return fail()
	}
	return w, nil
}

func (w *loadBalanceStreamInstalledContext) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || w.nss == nil || !w.nss.current() || !streamInstalledFixedRootCurrent(w.receiptRoot, loadBalanceStreamInstallationsRoot) || !streamInstalledFixedRootCurrent(w.observationRoot, loadBalanceStreamInstallObservationsRoot) {
		return errLoadBalanceStreamInstallationGate
	}
	if w == nil || ctx == nil || ctx.Err() != nil || w.module == nil || !w.module.current() || w.installed == nil || !w.installed.current() || w.journal == nil || w.submission == nil || !w.submission.current() || w.receiptRoot == nil || w.observationRoot == nil || w.engine == nil || !w.engine.current() || w.result.State != "committed" {
		return errLoadBalanceStreamInstallationGate
	}
	seed, records, chain, err := w.journal.original(ctx)
	if err != nil || !chain.Complete || chain.OriginalUnknown || len(records) != 6 || !bytes.Equal(seed, w.seedRaw) || core.Hash(string(seed)) != w.receipt.SeedSHA256 || core.Hash(string(records[5])) != w.receipt.FinalEventSHA256 {
		return errLoadBalanceStreamInstallationGate
	}
	if _, err = w.journal.officialAuthority(ctx); err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if !streamModulePublicationMatches(w.receiptRoot, w.receipt.InstallationID+".json", w.receiptRaw) || !streamModulePublicationMatches(w.observationRoot, w.receipt.JobID+".json", w.observationRaw) || core.Hash(string(w.installed.raw)) != w.receipt.PublishedModuleSHA256 {
		return errLoadBalanceStreamInstallationGate
	}
	var observed loadBalanceStreamObservedInstallExit
	if decodeProgramQueueJSON(w.observationRaw, &observed) != nil || observed.Format != 1 || !observed.OriginalStartWaitExitZero || observed.SubmissionSHA256 != core.Hash(string(w.submission.raw)) || observed.Result != w.result {
		return errLoadBalanceStreamInstallationGate
	}
	unit, err := loadbalancestream.AccountParentUnit(w.receipt.JobID)
	canonical, _ := json.Marshal(observed)
	if err != nil || observed.Unit != unit || !bytes.Equal(append(canonical, '\n'), w.observationRaw) {
		return errLoadBalanceStreamInstallationGate
	}
	if w.engine.release.ID != w.receipt.NginxReleaseID || w.engine.binary.sha != w.receipt.NginxSHA256 || w.engine.manifest.sha != w.receipt.NginxManifestSHA256 {
		return errLoadBalanceStreamInstallationGate
	}
	identity, accountSHA, err := loadBalanceStreamAccountReceiptHash(ctx)
	if err != nil || identity != w.identity || accountSHA != w.accountSHA || accountSHA != w.receipt.AccountReceiptSHA256 || identity.SHA256 != w.receipt.NSSSHA256 || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationGate
	}
	// Recheck the named original publication/backup/inode and sealed exit;
	// parsing them once is not lifetime authority or permission to recover.
	actual, err := readLoadBalanceStreamCommittedInstallation(ctx, w.receipt.JobID)
	if err != nil || actual != w.result || !w.nss.current() || !w.installed.current() || !w.engine.current() {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

func streamInstalledFixedRootCurrent(root *os.Root, path string) bool {
	if root == nil || path != loadBalanceStreamInstallationsRoot && path != loadBalanceStreamInstallObservationsRoot && path != loadBalanceStreamStateRoot && path != loadBalanceStreamGenerationPublicationsRoot && path != loadBalanceStreamConfigurationPublicationsRoot || root.Name() != path || threatIDSTrustedParents(path, false) != nil {
		return false
	}
	held, e1 := root.Stat(".")
	visible, e2 := os.Lstat(path)
	return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && memcachedUnixAdminDirectoryInfo(visible) && os.SameFile(held, visible)
}
