//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Read-only fixed-leaf bytes. The caller pins the independent fixed directory;
// no missing file, permission or original partial record is ever repaired.
func streamInstallationPrivateRead(root *os.Root, name string, limit int64) ([]byte, error) {
	if root == nil || limit < 1 || limit > loadBalanceStreamModuleLimit || filepath.Base(name) != name {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !streamJournalFileInfo(before, limit) {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	held, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() || !geoStoreStableInfo(before, held) || !geoStoreStableInfo(held, visible) {
		clear(raw)
		return nil, errLoadBalanceStreamInstallationJournal
	}
	return raw, nil
}

// One prerequisite for a completed installation observation. This reader
// proves actual journal/module/owned identity/native engine bytes but NEVER
// supplies a native-exit witness, current mutation grant or resume permission.
// Initial Core success additionally requires the submitter's once-only actual
// systemctl --wait exit observation, retained in its separate private record.
func readLoadBalanceStreamCommittedInstallation(ctx context.Context, job string) (core.LoadBalanceStreamInstallResult, error) {
	empty := core.LoadBalanceStreamInstallResult{}
	if ctx == nil || ctx.Err() != nil || !core.ValidID(job) || os.Geteuid() != 0 {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	j, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, job)
	if err != nil {
		return empty, err
	}
	defer j.close()
	seedRaw, records, chain, err := j.original(ctx)
	if err != nil || !chain.Complete || chain.OriginalUnknown || len(records) != 6 {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil || seed.JobID != job {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	if _, err := j.officialAuthority(ctx); err != nil {
		return empty, err
	}
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallationsRoot, false)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	raw, err := streamInstallationPrivateRead(root, seed.Nonce+".json", 8192)
	if err != nil {
		return empty, err
	}
	receipt, err := decodeStreamInstallationReceipt(raw)
	if err != nil || receipt.InstallationID != seed.Nonce || receipt.JobID != job || receipt.Version != seed.AppVersion || receipt.SeedSHA256 != core.Hash(string(seedRaw)) || receipt.FinalEventSHA256 != core.Hash(string(records[5])) || receipt.PublishedModuleSHA256 != chain.Events[5].PublishedModuleSHA256 || receipt.AccountReceiptSHA256 != chain.Events[5].AccountReceiptSHA256 || receipt.ProgrammeInputsSHA256 != seed.ProgrammeInputsSHA256 || receipt.EmptyConfigurationSHA256 != seed.EmptyConfigurationSHA {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	module, err := New(Config{}).moduleRecordDirectory("load-balance")
	if err != nil {
		return empty, err
	}
	defer module.Close()
	installed, err := holdLoadBalanceStreamModuleAt(module.Root, module.current)
	if err != nil {
		return empty, err
	}
	defer installed.close()
	if installed.missing || core.Hash(string(installed.raw)) != receipt.PublishedModuleSHA256 {
		return empty, errLoadBalanceStreamModule
	}
	manifest, err := decodeLoadBalanceStreamModule(installed.raw)
	if err != nil || manifest["version"] != receipt.Version || manifest["installation_id"] != receipt.InstallationID {
		return empty, errLoadBalanceStreamModule
	}
	publication, err := streamJournalAnchor(filepath.Join(loadBalanceStreamModulePublicationsRoot, job))
	if err != nil {
		return empty, err
	}
	defer publication.Close()
	proposal, err := streamInstallationPrivateRead(publication, "proposal.json", loadBalanceStreamModuleLimit)
	if err != nil {
		return empty, err
	}
	defer clear(proposal)
	if !bytes.Equal(proposal, installed.raw) {
		return empty, errLoadBalanceStreamModule
	}
	if err := checkStreamModulePublicationIntent(publication, module.Root, seedRaw, proposal); err != nil {
		return empty, err
	}
	if seed.Action == "update" {
		original, err := streamInstallationPrivateRead(publication, "original.json", loadBalanceStreamModuleLimit)
		if err != nil {
			return empty, err
		}
		defer clear(original)
		if core.Hash(string(original)) != seed.OriginalModuleSHA256 {
			return empty, errLoadBalanceStreamModule
		}
		old, err := readStreamRetainedOriginalModule(module.Root, job)
		if err != nil {
			return empty, err
		}
		defer clear(old)
		if !bytes.Equal(old, original) {
			return empty, errLoadBalanceStreamModule
		}
	}
	published, err := streamInstallationPrivateRead(publication, "published.json", 8192)
	if err != nil {
		return empty, err
	}
	var observed struct {
		Format                int    `json:"format"`
		JobID                 string `json:"job_id"`
		SeedSHA256            string `json:"seed_sha256"`
		PublishedSHA256       string `json:"published_sha256"`
		OriginalInodeRetained bool   `json:"original_inode_retained"`
	}
	if decodeProgramQueueJSON(published, &observed) != nil || observed.Format != 1 || observed.JobID != job || observed.SeedSHA256 != receipt.SeedSHA256 || observed.PublishedSHA256 != receipt.PublishedModuleSHA256 || observed.OriginalInodeRetained != (seed.Action == "update") {
		return empty, errLoadBalanceStreamModule
	}
	canonical, _ := json.Marshal(observed)
	if !bytes.Equal(append(canonical, '\n'), published) {
		return empty, errLoadBalanceStreamModule
	}
	identity, accountSHA, err := loadBalanceStreamAccountReceiptHash(ctx)
	if err != nil || accountSHA != receipt.AccountReceiptSHA256 || identity.SHA256 != receipt.NSSSHA256 {
		return empty, errLoadBalanceStreamAccount
	}
	engine, err := holdLoadBalanceStreamRecordedEngine(ctx, receipt.NginxReleaseID)
	if err != nil {
		return empty, err
	}
	defer engine.close()
	if engine.binary.sha != receipt.NginxSHA256 || engine.manifest.sha != receipt.NginxManifestSHA256 || !engine.current() || !installed.current() || !j.current() || ctx.Err() != nil {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	return core.LoadBalanceStreamInstallResult{Format: 1, JobID: job, Version: seed.AppVersion, State: "committed", InstallationID: receipt.InstallationID, SeedSHA256: receipt.SeedSHA256, FinalEventSHA256: receipt.FinalEventSHA256, PublishedModuleSHA256: receipt.PublishedModuleSHA256, AccountReceiptSHA256: receipt.AccountReceiptSHA256}, nil
}

// The complete copied bytes are not a substitute for retaining the ORIGINAL
// old inode and metadata. Rename legitimately changes ctime; every other old
// identity field is checked, including mode, owner, link count and nanosecond
// mtime. No repair, restore or caller-supplied identity is accepted here.
func checkStreamModulePublicationIntent(publication, module *os.Root, seedRaw, proposal []byte) error {
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil || publication == nil || module == nil {
		return errLoadBalanceStreamModule
	}
	raw, err := streamInstallationPrivateRead(publication, "intent.json", 8192)
	if err != nil {
		return err
	}
	var intent loadBalanceStreamModulePublicationIntent
	if decodeProgramQueueJSON(raw, &intent) != nil {
		return errLoadBalanceStreamModule
	}
	canonical, _ := json.Marshal(intent)
	if !bytes.Equal(append(canonical, '\n'), raw) || intent.Format != 1 || intent.JobID != seed.JobID || intent.SeedSHA256 != core.Hash(string(seedRaw)) || intent.ProposalSHA256 != core.Hash(string(proposal)) {
		return errLoadBalanceStreamModule
	}
	wanted := map[string]bool{"intent.json": true, "proposal.json": true, "published.json": true}
	if seed.Action == "update" {
		wanted["original.json"] = true
	}
	dir, err := publication.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(wanted) {
		return errLoadBalanceStreamModule
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] {
			return errLoadBalanceStreamModule
		}
	}
	name := ".lbstream-publication-" + seed.JobID + ".json"
	info, err := module.Lstat(name)
	if seed.Action == "install" {
		if !os.IsNotExist(err) || intent.Original != (loadBalanceStreamModuleOriginalIdentity{}) {
			return errLoadBalanceStreamModule
		}
		return nil
	}
	if err != nil || !streamModuleOriginalFileInfo(info) || !streamModuleRetainedIdentityMatches(intent.Original, info, seed.OriginalModuleSHA256) {
		return errLoadBalanceStreamModule
	}
	return nil
}

func streamModuleRetainedIdentityMatches(original loadBalanceStreamModuleOriginalIdentity, info os.FileInfo, digest string) bool {
	if info == nil {
		return false
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	return ok && original.Exists && original.SHA256 == digest && original.Device == uint64(v.Dev) && original.Inode == v.Ino && original.Mode == v.Mode && original.UID == v.Uid && original.GID == v.Gid && original.Links == uint64(v.Nlink) && original.Bytes == v.Size && original.MTimeSecond == v.Mtim.Sec && original.MTimeNano == v.Mtim.Nsec
}
