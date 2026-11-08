//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamStateRoot = "/var/lib/panel-executor/load-balance-stream-state"

// Held RECORDED generation only. Neither a completed JSON record nor its
// claimed observation hash proves today's daemon/listeners/cgroup or grants
// control. The eventual runtime controller must measure those independently.
type loadBalanceStreamHeldGeneration struct {
	root      *os.Root
	file      *os.File
	before    os.FileInfo
	raw       []byte
	value     loadbalancestream.GenerationRecord
	journal   *loadBalanceStreamJournal
	run       *streamHeldJournalFile
	installed *loadBalanceStreamInstalledContext
	source    *loadBalanceStreamCoreAuthority
	upgrade   *loadBalanceStreamTrafficUpgrade
}

func (r *loadBalanceStreamHeldGeneration) close() {
	if r == nil {
		return
	}
	if r.run != nil {
		r.run.close()
		r.run = nil
	}
	if r.journal != nil {
		r.journal.close()
		r.journal = nil
	}
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
	if r.root != nil {
		r.root.Close()
		r.root = nil
	}
	clear(r.raw)
}

// Fixed path, SELECT-only Core, immutable completed ORIGINAL control chain.
// No missing file/root is created, no pending operation resumed, and no
// version/UUID supplied by a caller chooses a host path.
func holdLoadBalanceStreamRecordedGeneration(ctx context.Context, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority) (*loadBalanceStreamHeldGeneration, error) {
	return holdLoadBalanceStreamRecordedGenerationForUpgrade(ctx, installed, source, nil)
}

// Only the programme reader can supply a closed historical inventory. The
// normal control reader still consults the unmodified live maintenance fence.
func holdLoadBalanceStreamRecordedGenerationForUpgrade(ctx context.Context, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority, upgrade *loadBalanceStreamTrafficUpgrade) (*loadBalanceStreamHeldGeneration, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || installed == nil || source == nil || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) || installed.current(ctx) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamStateRoot, false)
	if err != nil {
		return nil, err
	}
	r := &loadBalanceStreamHeldGeneration{root: root, installed: installed, source: source, upgrade: upgrade}
	fail := func() (*loadBalanceStreamHeldGeneration, error) {
		r.close()
		return nil, loadbalancestream.ErrGeneration
	}
	dir, err := root.Open(".")
	if err != nil {
		return fail()
	}
	entries, err := dir.ReadDir(2)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != 1 || entries[0].Name() != "current.json" {
		return fail()
	}
	r.file, err = root.OpenFile("current.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	r.before, err = r.file.Stat()
	if err != nil || !streamJournalFileInfo(r.before, loadbalancestream.MaxGenerationRecordBytes) {
		return fail()
	}
	r.raw, err = io.ReadAll(io.LimitReader(r.file, loadbalancestream.MaxGenerationRecordBytes+1))
	if err != nil || int64(len(r.raw)) != r.before.Size() {
		return fail()
	}
	r.value, err = loadbalancestream.DecodeGenerationRecord(r.raw)
	if err != nil || r.value.InstallationID != installed.receipt.InstallationID {
		return fail()
	}
	r.journal, err = openLoadBalanceStreamJournalReadOnlyAt(loadBalanceStreamJobsRoot, r.value.RequestID)
	if err != nil {
		return fail()
	}
	r.run, err = r.journal.read("run.lock", 0)
	if err != nil || streamLockRecordedGenerationRun(r.run.file) != nil {
		return fail()
	}
	if r.current(ctx) != nil {
		return fail()
	}
	return r, nil
}

// A completed journal is immutable recorded data. Its creators still take an
// exclusive run lock; shared readers exclude those writers while allowing
// status and programme observers to coexist. This grants no mutation authority.
func streamLockRecordedGenerationRun(file *os.File) error {
	if file == nil {
		return loadbalancestream.ErrGeneration
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
}

func (r *loadBalanceStreamHeldGeneration) current(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.root == nil || r.file == nil || r.journal == nil || r.run == nil || !r.run.current() || r.installed == nil || r.installed.current(ctx) != nil || r.source == nil {
		return loadbalancestream.ErrGeneration
	}
	if !streamInstalledFixedRootCurrent(r.root, loadBalanceStreamStateRoot) {
		return loadbalancestream.ErrGeneration
	}
	held, e1 := r.file.Stat()
	visible, e2 := r.root.Lstat("current.json")
	if e1 != nil || e2 != nil || !geoStoreStableInfo(r.before, held) || !geoStoreStableInfo(held, visible) {
		return loadbalancestream.ErrGeneration
	}
	seedRaw, records, chain, err := r.journal.original(ctx)
	if err != nil || !chain.Complete || chain.OriginalUnknown || !loadbalancestream.GenerationRecordBindsOriginal(r.raw, r.installed.receipt.InstallationID, r.value.Generation, seedRaw, records) {
		return loadbalancestream.ErrGeneration
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil || seed.Binding.InstalledSHA256 != core.Hash(string(r.installed.installed.raw)) {
		return loadbalancestream.ErrGeneration
	}
	installSeed, err := loadbalancestream.DecodeInstallationSeed(r.installed.seedRaw)
	if err != nil || seed.Binding.ManifestSHA256 != installSeed.ManifestSHA256 {
		return loadbalancestream.ErrGeneration
	}
	completion, err := streamGenerationRecordedCompletion(ctx, r.source, r.upgrade, seed.Operation)
	if err != nil || completion.OriginalRequestSHA256 != seed.Binding.OriginalRequestSHA256 {
		return loadbalancestream.ErrGeneration
	}
	if err != nil || completion.Format != 1 || completion.RequestID != r.value.RequestID || completion.OperationSHA256 != r.value.OperationSHA256 || completion.ManifestSHA256 != seed.Binding.ManifestSHA256 || completion.SeedSHA256 != r.value.SeedSHA256 || completion.FinalEventSHA256 != r.value.FinalEventSHA256 || completion.ConfigurationSHA256 != r.value.ConfigurationSHA256 || completion.ServiceObservationSHA256 != r.value.ServiceObservationSHA256 || !r.journal.current() || !r.run.current() || ctx.Err() != nil {
		return loadbalancestream.ErrGeneration
	}
	return checkStreamGenerationHistoryForUpgrade(ctx, r.raw, r.installed, r.source, r.upgrade)
}

func streamGenerationRecordedCompletion(ctx context.Context, source *loadBalanceStreamCoreAuthority, upgrade *loadBalanceStreamTrafficUpgrade, op loadbalancestream.Operation) (core.LoadBalanceStreamControlCompletion, error) {
	if upgrade != nil {
		if source == nil || upgrade.source != source {
			return core.LoadBalanceStreamControlCompletion{}, errLoadBalanceStreamCoreAuthority
		}
		return upgrade.recordedCompletion(ctx, op)
	}
	return source.controlCompletion(ctx, op)
}
