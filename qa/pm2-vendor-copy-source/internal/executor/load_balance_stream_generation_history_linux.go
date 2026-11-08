//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Historical check only; nothing is repaired or created. The actual previous
// inode, complete original bytes/metadata and closed publication inventory are
// required. A copied/relabelled predecessor or self-reported counter refuses.
func checkStreamGenerationPublication(publication *os.Root, seedRaw, proposal []byte) ([]byte, error) {
	if publication == nil {
		return nil, loadbalancestream.ErrGeneration
	}
	rootInfo, err := publication.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(rootInfo) {
		return nil, loadbalancestream.ErrGeneration
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	v, e2 := loadbalancestream.DecodeGenerationRecord(proposal)
	if err != nil || e2 != nil || v.RequestID != seed.Operation.RequestID || v.SeedSHA256 != core.Hash(string(seedRaw)) || !streamModulePublicationMatches(publication, "proposal.json", proposal) {
		return nil, loadbalancestream.ErrGeneration
	}
	raw, err := streamInstallationPrivateRead(publication, "intent.json", 8192)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	var intent loadBalanceStreamGenerationIntent
	if decodeProgramQueueJSON(raw, &intent) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	canonical, _ := json.Marshal(intent)
	if !bytes.Equal(append(canonical, '\n'), raw) || intent.Format != 1 || intent.RequestID != v.RequestID || intent.InstallationID != v.InstallationID || intent.Generation != v.Generation || intent.SeedSHA256 != v.SeedSHA256 || intent.ProposalSHA256 != core.Hash(string(proposal)) {
		return nil, loadbalancestream.ErrGeneration
	}
	want := map[string]bool{"intent.json": true, "proposal.json": true}
	if v.Generation > 1 {
		want["original.json"], want["candidate.json"] = true, true
	}
	dir, err := publication.Open(".")
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(want) {
		return nil, loadbalancestream.ErrGeneration
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return nil, loadbalancestream.ErrGeneration
		}
	}
	if v.Generation == 1 {
		if intent.Original != (loadBalanceStreamModuleOriginalIdentity{}) || len(seed.Before) != 0 {
			return nil, loadbalancestream.ErrGeneration
		}
		return nil, nil
	}
	previousRaw, err := streamInstallationPrivateRead(publication, "original.json", loadbalancestream.MaxGenerationRecordBytes)
	if err != nil || !streamModulePublicationMatches(publication, "candidate.json", previousRaw) {
		return nil, loadbalancestream.ErrGeneration
	}
	previous, err := loadbalancestream.DecodeGenerationRecord(previousRaw)
	retained, e2 := publication.Lstat("candidate.json")
	if err != nil || e2 != nil || !streamJournalFileInfo(retained, loadbalancestream.MaxGenerationRecordBytes) || !streamModuleRetainedIdentityMatches(intent.Original, retained, core.Hash(string(previousRaw))) || previous.InstallationID != v.InstallationID || previous.Generation+1 != v.Generation || previous.RequestID == v.RequestID || !reflect.DeepEqual(previous.Entries, seed.Before) || previous.ConfigurationSHA256 != seed.BeforeRuntimeSHA256 {
		return nil, loadbalancestream.ErrGeneration
	}
	return previousRaw, nil
}

// Full bounded lineage, not just today's self-labelled generation. EVERY
// predecessor must have its original persisted twelve-event Root chain and
// historical committed Core result. This grants no current actor authority
// and never treats an incomplete prior generation as recovery permission.
func checkStreamGenerationHistory(ctx context.Context, raw []byte, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority) error {
	return checkStreamGenerationHistoryForUpgrade(ctx, raw, installed, source, nil)
}

func checkStreamGenerationHistoryForUpgrade(ctx context.Context, raw []byte, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority, upgrade *loadBalanceStreamTrafficUpgrade) error {
	if ctx == nil || ctx.Err() != nil || installed == nil || source == nil || installed.current(ctx) != nil {
		return loadbalancestream.ErrGeneration
	}
	anchor, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamGenerationPublicationsRoot, false)
	if err != nil {
		return loadbalancestream.ErrGeneration
	}
	defer anchor.Close()
	seen := map[string]bool{}
	for n := 0; n < 128; n++ {
		v, err := loadbalancestream.DecodeGenerationRecord(raw)
		if err != nil || v.InstallationID != installed.receipt.InstallationID || seen[v.RequestID] || v.Generation > 128 || ctx.Err() != nil {
			return loadbalancestream.ErrGeneration
		}
		seen[v.RequestID] = true
		previous, err := func() ([]byte, error) {
			publication, err := anchor.OpenRoot(v.RequestID)
			if err != nil {
				return nil, loadbalancestream.ErrGeneration
			}
			defer publication.Close()
			before, e1 := publication.Stat(".")
			visible, e2 := anchor.Lstat(v.RequestID)
			if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(before) || !geoStoreStableInfo(before, visible) {
				return nil, loadbalancestream.ErrGeneration
			}
			j, err := openLoadBalanceStreamJournalReadOnlyAt(loadBalanceStreamJobsRoot, v.RequestID)
			if err != nil {
				return nil, loadbalancestream.ErrGeneration
			}
			defer j.close()
			seedRaw, records, chain, err := j.original(ctx)
			if err != nil || !chain.Complete || chain.OriginalUnknown || !loadbalancestream.GenerationRecordBindsOriginal(raw, installed.receipt.InstallationID, v.Generation, seedRaw, records) {
				return nil, loadbalancestream.ErrGeneration
			}
			seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
			if err != nil || seed.Binding.InstalledSHA256 != core.Hash(string(installed.installed.raw)) {
				return nil, loadbalancestream.ErrGeneration
			}
			completion, err := streamGenerationRecordedCompletion(ctx, source, upgrade, seed.Operation)
			if err != nil || completion.OriginalRequestSHA256 != seed.Binding.OriginalRequestSHA256 {
				return nil, loadbalancestream.ErrGeneration
			}
			if err != nil || completion.Format != 1 || completion.RequestID != v.RequestID || completion.OperationSHA256 != v.OperationSHA256 || completion.ManifestSHA256 != seed.Binding.ManifestSHA256 || completion.SeedSHA256 != v.SeedSHA256 || completion.FinalEventSHA256 != v.FinalEventSHA256 || completion.ConfigurationSHA256 != v.ConfigurationSHA256 || completion.ServiceObservationSHA256 != v.ServiceObservationSHA256 {
				return nil, loadbalancestream.ErrGeneration
			}
			previous, err := checkStreamGenerationPublication(publication, seedRaw, raw)
			after, e1 := publication.Stat(".")
			named, e2 := anchor.Lstat(v.RequestID)
			if err != nil || e1 != nil || e2 != nil || !geoStoreStableInfo(before, after) || !geoStoreStableInfo(after, named) || !j.current() {
				return nil, loadbalancestream.ErrGeneration
			}
			return previous, nil
		}()
		if err != nil {
			return loadbalancestream.ErrGeneration
		}
		if previous == nil {
			if v.Generation != 1 || !streamInstalledFixedRootCurrent(anchor, loadBalanceStreamGenerationPublicationsRoot) || installed.current(ctx) != nil || ctx.Err() != nil {
				return loadbalancestream.ErrGeneration
			}
			return nil
		}
		raw = previous
	}
	return loadbalancestream.ErrGeneration
}
