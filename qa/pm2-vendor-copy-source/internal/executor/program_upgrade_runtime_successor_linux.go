//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

type runtimePHPPublisherWitness struct {
	evidence core.RuntimeSupersededCompileOOMEvidence
	current  func() bool
	final    func() bool
	close    func()
	binding  string
}

// The native-start and global build read leases are already held by the
// caller. No filesystem adoption, record repair, service action or counter
// reset occurs here. Hold descriptors, repeat every path/metadata identity and
// require a final byte rehash under the original five-second budget.
func holdRuntimePHPPublisher(ctx context.Context, records *os.Root, original InstallStatus) (_ *runtimePHPPublisherWitness, ret error) {
	r, found := runtimecatalog.Find(original.ReleaseID)
	if !found || r.Family != "php" || !core.ValidID(original.JobID) || ctx.Err() != nil {
		return nil, errRuntimePHPPublication
	}
	ancestry, err := runtimePHPPublicationAncestry(r.Prefix())
	if err != nil {
		return nil, err
	}
	return holdRuntimePHPPublisherTree(ctx, records, original, r.Prefix(), ancestry)
}

// Isolated private Root tree seam, not an alternate-root CLI or API. The only
// production call above always binds the exact catalogue prefix and ancestry.
func holdRuntimePHPPublisherTree(ctx context.Context, records *os.Root, original InstallStatus, prefix string, ancestry []programQueueSnapshot) (_ *runtimePHPPublisherWitness, ret error) {
	r, found := runtimecatalog.Find(original.ReleaseID)
	if !found || r.Family != "php" || !core.ValidID(original.JobID) || ctx.Err() != nil || len(ancestry) == 0 || ancestry[0].path != prefix || !runtimePHPAncestryCurrent(ancestry) {
		return nil, errRuntimePHPPublication
	}
	tree, err := holdRuntimePHPFiles(ctx, prefix, runtime.GOARCH, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if ret != nil {
			tree.close()
		}
	}()
	var manifest RuntimeManifest
	if json.Unmarshal(tree.manifest, &manifest) != nil {
		return nil, errRuntimePHPPublication
	}
	canonical, err := json.MarshalIndent(manifest, "", "  ")
	seal := manifest.Publication
	if err != nil || !bytes.Equal(canonical, tree.manifest) || manifest.Release != r || manifest.Architecture != runtime.GOARCH || seal == nil || seal.Format != 1 || !core.ValidID(seal.JobID) || seal.JobID == original.JobID || seal.SourceSHA256 != r.SHA256 || len(seal.Artifacts) != 2 {
		return nil, errRuntimePHPPublication
	}
	for _, name := range []string{"bin/php", "sbin/php-fpm"} {
		if seal.Artifacts[name] != tree.artifacts[name] {
			return nil, errRuntimePHPPublication
		}
	}
	publisherInfo, err := records.Lstat(seal.JobID + ".json")
	if err != nil || !runtimeInstallPrivateFile(publisherInfo) {
		return nil, errRuntimePHPPublication
	}
	raw, err := readRuntimeInstallPrivateFile(records, seal.JobID+".json")
	if err != nil {
		return nil, err
	}
	var publisher InstallStatus
	if json.Unmarshal(raw, &publisher) != nil || validateRuntimeInstallStatus(publisher, seal.JobID) != nil || publisher.ReleaseID != r.ID || publisher.ExtensionID != "" || publisher.State != "succeeded" || publisher.Error != "" || !core.RuntimePHPPublicationSteps(r.ID, publisher.Steps) {
		return nil, errRuntimePHPPublication
	}
	canonical, err = json.Marshal(publisher)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errRuntimePHPPublication
	}
	current := func() bool {
		if !tree.current(ctx) || !runtimePHPAncestryCurrent(ancestry) {
			return false
		}
		for _, id := range []string{original.JobID, publisher.JobID} {
			if _, err := os.Lstat(prefix + ".pending-" + id); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
		latest, err := readRuntimeInstallPrivateFile(records, publisher.JobID+".json")
		info, e2 := records.Lstat(publisher.JobID + ".json")
		return err == nil && e2 == nil && bytes.Equal(raw, latest) && runtimeInstallSamePrivateFile(publisherInfo, info)
	}
	if !current() {
		return nil, errRuntimePHPPublication
	}
	evidence := core.RuntimeSupersededCompileOOMEvidence{Original: core.RuntimeCompileOOMInstallEvidence{JobID: original.JobID, ReleaseID: original.ReleaseID, Steps: original.Steps}, PublisherJobID: publisher.JobID, PublisherSteps: publisher.Steps, Architecture: manifest.Architecture, InstalledAt: manifest.InstalledAt}
	final := func() bool { return current() && tree.bytesCurrent(ctx) && current() }
	return &runtimePHPPublisherWitness{evidence: evidence, current: current, final: final, close: tree.close, binding: core.Hash("php-publisher-seal-v1\x00" + original.JobID + "\x00" + string(tree.manifest) + "\x00" + string(raw))}, nil
}

// Independent from the old unpublished proof. Both remain fail-closed; this
// path requires additional successful publisher authority instead of treating
// an arbitrary existing directory as harmless. Fixture seams are unexported.
type runtimeSupersededCompileOOMProof struct {
	open       func() (*os.Root, error)
	current    func(*os.Root) bool
	stopped    func() (string, error)
	fence      func() (func() bool, func(), error)
	publisher  func(context.Context, *os.Root, InstallStatus) (*runtimePHPPublisherWitness, error)
	validate   func(context.Context, core.RuntimeSupersededCompileOOMEvidence) (string, error)
	checkpoint func() error
}

func (p runtimeSupersededCompileOOMProof) check(ctx context.Context, id string) error {
	bad := errors.New("原始 OOM 与独立 PHP 成功发布来源未完整闭合；阻止程序升级")
	if ctx.Err() != nil || !core.ValidID(id) || p.open == nil || p.current == nil || p.stopped == nil || p.fence == nil || p.publisher == nil || p.validate == nil {
		return bad
	}
	show, err := p.stopped()
	generation, valid := runtimeCompileOOMUnitStopped(show)
	if err != nil || !valid {
		return bad
	}
	records, err := p.open()
	if err != nil {
		return bad
	}
	defer records.Close()
	if !p.current(records) {
		return bad
	}
	lock, lockInfo, err := runtimeCompileOOMReadLease(records, ".native-start.lock")
	if err != nil {
		return bad
	}
	defer lock.Close()
	fenceCurrent, closeFence, err := p.fence()
	if err != nil || fenceCurrent == nil || closeFence == nil {
		return bad
	}
	defer closeFence()
	if !fenceCurrent() {
		return bad
	}
	info, err := records.Lstat(id + ".json")
	if err != nil || !runtimeInstallPrivateFile(info) {
		return bad
	}
	raw, err := readRuntimeInstallPrivateFile(records, id+".json")
	var original InstallStatus
	if err != nil || json.Unmarshal(raw, &original) != nil || validateRuntimeInstallStatus(original, id) != nil || original.ExtensionID != "" || original.State != "running" || original.Error != "" || !core.RuntimeCompileOOMSteps(original.ReleaseID, original.Steps) {
		return bad
	}
	canonical, _ := json.Marshal(original)
	if !bytes.Equal(raw, canonical) {
		return bad
	}
	w, err := p.publisher(ctx, records, original)
	if err != nil || w == nil || w.current == nil || w.final == nil || w.close == nil {
		return bad
	}
	defer w.close()
	// The reader cannot substitute another original job or steps for validation.
	boundOriginal, _ := json.Marshal(w.evidence.Original)
	wantOriginal, _ := json.Marshal(core.RuntimeCompileOOMInstallEvidence{JobID: original.JobID, ReleaseID: original.ReleaseID, Steps: original.Steps})
	if !bytes.Equal(boundOriginal, wantOriginal) || w.evidence.PublisherJobID == id || !core.ValidID(w.evidence.PublisherJobID) || !programQueueDiagnosticSHA.MatchString(w.binding) || !w.current() {
		return bad
	}
	bound, err := p.validate(ctx, w.evidence)
	if err != nil || !programQueueDiagnosticSHA.MatchString(bound) {
		return bad
	}
	if p.checkpoint != nil {
		if err := p.checkpoint(); err != nil {
			return err
		}
	}
	last, err := readRuntimeInstallPrivateFile(records, id+".json")
	latestInfo, e2 := records.Lstat(id + ".json")
	if err != nil || e2 != nil || !bytes.Equal(raw, last) || !runtimeInstallSamePrivateFile(info, latestInfo) || !w.current() || !runtimeCompileOOMLeaseCurrent(records, ".native-start.lock", lock, lockInfo) || !p.current(records) || !fenceCurrent() {
		return bad
	}
	finalBound, err := p.validate(ctx, w.evidence)
	if err != nil || finalBound != bound {
		return bad
	}
	show, err = p.stopped()
	finalGeneration, valid := runtimeCompileOOMUnitStopped(show)
	if err != nil || !valid || finalGeneration != generation || ctx.Err() != nil || !w.current() || !fenceCurrent() || !runtimeCompileOOMLeaseCurrent(records, ".native-start.lock", lock, lockInfo) || !p.current(records) {
		return bad
	}
	if !w.final() || !fenceCurrent() || !runtimeCompileOOMLeaseCurrent(records, ".native-start.lock", lock, lockInfo) || !p.current(records) || ctx.Err() != nil {
		return bad
	}
	return nil
}

func closedRuntimeSupersededCompileOOMInstall(ctx context.Context, name string, run Command) bool {
	id, valid := runtimeFailedUnitID(name)
	if !valid || os.Geteuid() != 0 || ctx.Err() != nil || !runtimeFailedAncestry() {
		return false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false
	}
	defer reader.db.Close()
	p := runtimeSupersededCompileOOMProof{open: runtimeInstallRecordRoot, current: runtimeFailedRootCurrent, fence: runtimeCompileOOMBuildFence, publisher: holdRuntimePHPPublisher,
		stopped: func() (string, error) {
			return run(ctx, "/usr/bin/systemctl", "show", name, "--property="+runtimeFailedUnitProperties, "--no-pager")
		},
		validate: func(ctx context.Context, evidence core.RuntimeSupersededCompileOOMEvidence) (string, error) {
			if !reader.current() {
				return "", errRuntimePHPPublication
			}
			digest, err := (&core.Store{DB: reader.db}).ValidateRuntimeSupersededCompileOOMInstall(ctx, evidence)
			if !reader.current() {
				return "", errRuntimePHPPublication
			}
			return digest, err
		},
	}
	return p.check(ctx, id) == nil
}
