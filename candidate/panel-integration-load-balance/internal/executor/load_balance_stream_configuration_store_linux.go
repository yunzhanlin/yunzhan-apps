//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Serialized BEFORE-state only, not native control or recovery permission.
// The first absent namespace may be created only by the later original owner
// in configuration-intent; readers never initialize, repair or adopt it.
type loadBalanceStreamConfigurationStore struct {
	installed          *loadBalanceStreamInstalledContext
	source             *loadBalanceStreamCoreAuthority
	lifetime           *memcachedUnixRuntimeLease
	mutation           *loadBalanceStreamMutationLease
	original           core.LoadBalanceStreamAuthority
	operation          loadbalancestream.Operation
	generation         *loadBalanceStreamHeldGeneration
	root, publications *os.Root
	file               *loadBalanceStreamConfigurationFile
	first              bool
	closed             map[string]bool
	released           bool
	priorService       *loadBalanceStreamServiceObservation
	priorStopped       bool
	priorCaptured      bool
	priorColdBoot      *loadBalanceStreamColdBootWitness
	egress             *loadBalanceStreamHeldEgress
}

func (s *loadBalanceStreamConfigurationStore) close() {
	if s != nil {
		s.released = true
		if s.egress != nil {
			s.egress.close()
			s.egress = nil
		}
		if s.priorService != nil {
			s.priorService.close()
			s.priorService = nil
		}
		if s.file != nil {
			s.file.close()
			s.file = nil
		}
		if s.root != nil {
			s.root.Close()
			s.root = nil
		}
		if s.publications != nil {
			s.publications.Close()
			s.publications = nil
		}
		if s.generation != nil {
			s.generation.close()
			s.generation = nil
		}
	}
}

func streamConfigurationNamedRootCurrent(root *os.Root, gid uint32) bool {
	if root == nil || root.Name() != loadBalanceStreamConfigurationRoot || threatIDSTrustedParents(filepath.Dir(loadBalanceStreamConfigurationRoot), false) != nil {
		return false
	}
	a, e1 := root.Stat(".")
	b, e2 := os.Lstat(loadBalanceStreamConfigurationRoot)
	return e1 == nil && e2 == nil && streamConfigurationInfo(a, gid, true) && streamConfigurationInfo(b, gid, true) && os.SameFile(a, b)
}

func (s *loadBalanceStreamConfigurationStore) beforeCurrent(ctx context.Context) error {
	if s == nil || s.released || ctx == nil || ctx.Err() != nil || s.installed == nil || s.installed.current(ctx) != nil || s.source == nil || s.lifetime == nil || !s.lifetime.current() || s.mutation == nil || !s.mutation.current() || !streamControlHeldLease(s.lifetime.file.file, false) || !streamControlHeldLease(s.mutation.file, true) {
		return loadbalancestream.ErrRuntime
	}
	actual, err := s.source.controlAuthority(ctx, s.operation)
	if err != nil || actual != s.original {
		return loadbalancestream.ErrRuntime
	}
	if s.generation != nil && s.generation.current(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	if s.priorColdBoot != nil && s.priorColdBoot.current(ctx, s) != nil {
		return loadbalancestream.ErrRuntime
	}
	if s.egress != nil && s.egress.current(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	if s.root == nil {
		if !s.first {
			return loadbalancestream.ErrRuntime
		}
		if _, err := os.Lstat(loadBalanceStreamConfigurationRoot); !errors.Is(err, os.ErrNotExist) {
			return loadbalancestream.ErrRuntime
		}
	} else if s.file == nil || !s.file.current() || !streamConfigurationNamedRootCurrent(s.root, s.installed.identity.GID) {
		return loadbalancestream.ErrRuntime
	}
	return nil
}

// Fixed native namespace census. The expected set is constructed from actual
// canonical Core completions, never a caller-supplied list or prefix exemption.
func streamConfigurationExactDirectories(root *os.Root, expected map[string]bool) error {
	if root == nil {
		return loadbalancestream.ErrRuntime
	}
	info, err := root.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		return loadbalancestream.ErrRuntime
	}
	dir, err := root.Open(".")
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	entries, err := dir.ReadDir(129)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(expected) || len(entries) > 128 {
		return loadbalancestream.ErrRuntime
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil || !expected[entry.Name()] || !core.ValidID(entry.Name()) || !memcachedUnixAdminDirectoryInfo(info) {
			return loadbalancestream.ErrRuntime
		}
	}
	return nil
}

func holdLoadBalanceStreamConfigurationStore(ctx context.Context, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority, lifetime *memcachedUnixRuntimeLease, mutation *loadBalanceStreamMutationLease, original core.LoadBalanceStreamAuthority) (*loadBalanceStreamConfigurationStore, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || installed == nil || installed.current(ctx) != nil || source == nil || lifetime == nil || !lifetime.current() || mutation == nil || !mutation.current() || !streamControlHeldLease(lifetime.file.file, false) || !streamControlHeldLease(mutation.file, true) {
		return nil, loadbalancestream.ErrRuntime
	}
	s := &loadBalanceStreamConfigurationStore{installed: installed, source: source, lifetime: lifetime, mutation: mutation, original: original}
	fail := func() (*loadBalanceStreamConfigurationStore, error) {
		s.close()
		return nil, loadbalancestream.ErrRuntime
	}
	history, err := source.controlUpgradeHistory(ctx, &original)
	if err != nil {
		return fail()
	}
	closed := map[string]bool{}
	own := 0
	for _, row := range history {
		if row.Operation.RequestID == original.RequestID {
			if row.State != "issued" {
				return fail()
			}
			s.operation = row.Operation
			own++
			continue
		}
		if row.State != "completed" {
			return fail()
		}
		if row.ResultState == "committed" {
			closed[row.Operation.RequestID] = true
		} else if row.ResultState != "refused-before-issue" && row.ResultState != "refused-before-effects" {
			return fail()
		}
	}
	if own != 1 || len(closed) > 128 {
		return fail()
	}
	s.closed = closed
	// This loader is BEFORE exclusive original journal creation. Any own old
	// Root directory means a previous dispatch, not permission to resume it.
	_, statErr := os.Lstat(loadBalanceStreamJobsRoot)
	if errors.Is(statErr, os.ErrNotExist) && len(closed) == 0 {
	} else if statErr != nil {
		return fail()
	} else {
		jobs, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamJobsRoot, false)
		if err != nil {
			return fail()
		}
		if streamConfigurationExactDirectories(jobs, closed) != nil {
			jobs.Close()
			return fail()
		}
		jobs.Close()
	}
	if len(closed) == 0 {
		s.first = true
		for _, path := range []string{loadBalanceStreamConfigurationRoot, loadBalanceStreamConfigurationPublicationsRoot, loadBalanceStreamStateRoot, loadBalanceStreamGenerationPublicationsRoot} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return fail()
			}
		}
		if s.beforeCurrent(ctx) != nil {
			return fail()
		}
		return s, nil
	}
	if s.holdCompletedConfiguration(ctx) != nil || s.beforeCurrent(ctx) != nil {
		return fail()
	}
	return s, nil
}

// Historical reader only. It cannot authorize a write: beforeCurrent still
// independently requires the live full Core grant and both real held leases.
// Upgrade admission uses the same full configuration/publication lineage, but
// never initializes directories or borrows an old actor's control authority.
func (s *loadBalanceStreamConfigurationStore) holdCompletedConfiguration(ctx context.Context) error {
	if s == nil || s.released || ctx == nil || ctx.Err() != nil || s.installed == nil || s.source == nil || len(s.closed) == 0 || len(s.closed) > 128 || s.generation != nil || s.root != nil || s.file != nil || s.publications != nil {
		return loadbalancestream.ErrRuntime
	}
	installed, source, closed := s.installed, s.source, s.closed
	var err error
	s.generation, err = holdLoadBalanceStreamRecordedGeneration(ctx, installed, source)
	if err != nil || s.generation.value.Generation != int64(len(closed)) {
		return loadbalancestream.ErrRuntime
	}
	if threatIDSTrustedParents(loadBalanceStreamConfigurationRoot, false) != nil {
		return loadbalancestream.ErrRuntime
	}
	s.root, err = os.OpenRoot(loadBalanceStreamConfigurationRoot)
	if err != nil || !streamConfigurationNamedRootCurrent(s.root, installed.identity.GID) {
		return loadbalancestream.ErrRuntime
	}
	s.file, err = holdStreamConfigurationAt(s.root, installed.identity.GID, func() bool { return streamConfigurationNamedRootCurrent(s.root, installed.identity.GID) })
	if err != nil || s.file.missing || core.Hash(string(s.file.raw)) != s.generation.value.ConfigurationSHA256 {
		return loadbalancestream.ErrRuntime
	}
	s.publications, err = openLoadBalanceStreamFixedRoot(loadBalanceStreamConfigurationPublicationsRoot, false)
	if err != nil || streamConfigurationExactDirectories(s.publications, closed) != nil {
		return loadbalancestream.ErrRuntime
	}
	return s.checkPublicationLineage(ctx, closed)
}

func (s *loadBalanceStreamConfigurationStore) checkPublicationLineage(ctx context.Context, closed map[string]bool) error {
	if s == nil || s.generation == nil || s.publications == nil || s.root == nil {
		return loadbalancestream.ErrRuntime
	}
	genPublications, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamGenerationPublicationsRoot, false)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	defer genPublications.Close()
	if streamConfigurationExactDirectories(genPublications, closed) != nil {
		return loadbalancestream.ErrRuntime
	}
	raw := s.generation.raw
	seen := map[string]bool{}
	leaves := map[string]bool{"nginx.conf": true}
	var nextOriginal *loadBalanceStreamModuleOriginalIdentity
	for n := 0; n < 128; n++ {
		g, err := loadbalancestream.DecodeGenerationRecord(raw)
		if err != nil || !closed[g.RequestID] || seen[g.RequestID] || g.Generation != s.generation.value.Generation-int64(n) || ctx.Err() != nil {
			return loadbalancestream.ErrRuntime
		}
		seen[g.RequestID] = true
		previous, err := func() ([]byte, error) {
			j, err := openLoadBalanceStreamJournalReadOnlyAt(loadBalanceStreamJobsRoot, g.RequestID)
			if err != nil {
				return nil, loadbalancestream.ErrRuntime
			}
			defer j.close()
			seed, records, chain, err := j.original(ctx)
			if err != nil || !chain.Complete || !loadbalancestream.GenerationRecordBindsOriginal(raw, s.installed.receipt.InstallationID, g.Generation, seed, records) {
				return nil, loadbalancestream.ErrRuntime
			}
			pub, err := s.publications.OpenRoot(g.RequestID)
			if err != nil {
				return nil, loadbalancestream.ErrRuntime
			}
			defer pub.Close()
			h, err := checkStreamConfigurationPublication(pub, s.root, seed, s.installed.identity.GID, n == 0)
			if err != nil || h.Intent.ConfigurationSHA256 != g.ConfigurationSHA256 || len(h.ServiceReceipt) == 0 || core.Hash(string(h.ServiceReceipt)) != g.ServiceObservationSHA256 || len(h.CompletionReceipt) == 0 || nextOriginal != nil && h.Promoted.File != *nextOriginal {
				return nil, loadbalancestream.ErrRuntime
			}
			completion, err := decodeStreamControlCompletion(h.CompletionReceipt, seed)
			if err != nil || completion.Generation != g.Generation || completion.GenerationSHA256 != core.Hash(string(raw)) || core.Hash(completion.Records[len(completion.Records)-1]) != g.FinalEventSHA256 {
				return nil, loadbalancestream.ErrRuntime
			}
			if h.Intent.Original.Exists {
				leaves[".candidate-"+g.RequestID+".conf"] = true
			}
			x := h.Intent.Original
			nextOriginal = &x
			gp, err := genPublications.OpenRoot(g.RequestID)
			if err != nil {
				return nil, loadbalancestream.ErrRuntime
			}
			defer gp.Close()
			previous, err := checkStreamGenerationPublication(gp, seed, raw)
			if err != nil || !j.current() {
				return nil, loadbalancestream.ErrRuntime
			}
			return previous, nil
		}()
		if err != nil {
			return loadbalancestream.ErrRuntime
		}
		if previous == nil {
			if g.Generation != 1 || len(seen) != len(closed) {
				return loadbalancestream.ErrRuntime
			}
			break
		}
		raw = previous
	}
	if len(seen) != len(closed) {
		return loadbalancestream.ErrRuntime
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	entries, err := dir.ReadDir(130)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(leaves) {
		return loadbalancestream.ErrRuntime
	}
	for _, entry := range entries {
		info, err := s.root.Lstat(entry.Name())
		if err != nil || !leaves[entry.Name()] || !streamConfigurationInfo(info, s.installed.identity.GID, false) {
			return loadbalancestream.ErrRuntime
		}
	}
	if !streamInstalledFixedRootCurrent(genPublications, loadBalanceStreamGenerationPublicationsRoot) || !streamInstalledFixedRootCurrent(s.publications, loadBalanceStreamConfigurationPublicationsRoot) || !s.file.current() {
		return loadbalancestream.ErrRuntime
	}
	return nil
}

// A fixed-path first directory can be created only by the fresh original
// controller in its durable configuration-intent phase. Existing directories
// are never chowned/chmodded or adopted, including empty orphan directories.
func (s *loadBalanceStreamConfigurationStore) prepareDirectory(ctx context.Context, w *loadBalanceStreamControlOwner) error {
	raw, err := w.configurationPhase(ctx, "configuration-intent")
	if err != nil || s == nil || s.installed != w.gate.installed || s.source != w.gate.source || s.lifetime != w.lifetime || s.mutation != w.mutation || s.original != w.gate.original || s.beforeCurrent(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || seed.Operation.RequestID != s.original.RequestID {
		return loadbalancestream.ErrRuntime
	}
	if !s.first {
		if s.root == nil || s.file == nil || s.file.missing {
			return loadbalancestream.ErrRuntime
		}
		return nil
	}
	if s.root != nil || len(seed.Before) != 0 || threatIDSTrustedParents(filepath.Dir(loadBalanceStreamConfigurationRoot), false) != nil {
		return loadbalancestream.ErrRuntime
	}
	parent, err := os.OpenRoot(filepath.Dir(loadBalanceStreamConfigurationRoot))
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	defer parent.Close()
	name := filepath.Base(loadBalanceStreamConfigurationRoot)
	if _, err := parent.Lstat(name); !errors.Is(err, os.ErrNotExist) || w.current(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	if parent.Mkdir(name, 0700) != nil {
		return loadbalancestream.ErrRuntime
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	defer child.Close()
	f, err := child.Open(".")
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	defer f.Close()
	if f.Chown(0, int(s.installed.identity.GID)) != nil || f.Chmod(0750) != nil || f.Sync() != nil || ruleFeedStoreSync(parent) != nil || w.current(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	s.root, err = os.OpenRoot(loadBalanceStreamConfigurationRoot)
	if err != nil || !streamConfigurationNamedRootCurrent(s.root, s.installed.identity.GID) {
		return loadbalancestream.ErrRuntime
	}
	s.file, err = holdStreamConfigurationAt(s.root, s.installed.identity.GID, func() bool { return streamConfigurationNamedRootCurrent(s.root, s.installed.identity.GID) })
	if err != nil || !s.file.missing || s.beforeCurrent(ctx) != nil {
		return loadbalancestream.ErrRuntime
	}
	return nil
}

func (s *loadBalanceStreamConfigurationStore) stage(ctx context.Context, w *loadBalanceStreamControlOwner) (*loadBalanceStreamConfigurationPublication, error) {
	if s == nil || s.prepareDirectory(ctx, w) != nil || s.beforeCurrent(ctx) != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	raw, err := w.configurationPhase(ctx, "configuration-intent")
	if err != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || seed.Operation.RequestID != s.original.RequestID {
		return nil, loadbalancestream.ErrRuntime
	}
	if s.capturePriorService(ctx, w, seed) != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	if s.publications == nil {
		if !s.first || len(s.closed) != 0 || threatIDSTrustedParents(filepath.Dir(loadBalanceStreamConfigurationPublicationsRoot), false) != nil {
			return nil, loadbalancestream.ErrRuntime
		}
		if _, err := os.Lstat(loadBalanceStreamConfigurationPublicationsRoot); !errors.Is(err, os.ErrNotExist) {
			return nil, loadbalancestream.ErrRuntime
		}
		parent, err := os.OpenRoot(filepath.Dir(loadBalanceStreamConfigurationPublicationsRoot))
		if err != nil {
			return nil, loadbalancestream.ErrRuntime
		}
		if w.current(ctx) != nil || createStreamRootPrivateDirectory(parent, filepath.Base(loadBalanceStreamConfigurationPublicationsRoot)) != nil {
			parent.Close()
			return nil, loadbalancestream.ErrRuntime
		}
		parent.Close()
		s.publications, err = openLoadBalanceStreamFixedRoot(loadBalanceStreamConfigurationPublicationsRoot, false)
		if err != nil {
			return nil, loadbalancestream.ErrRuntime
		}
	}
	if !streamInstalledFixedRootCurrent(s.publications, loadBalanceStreamConfigurationPublicationsRoot) || streamConfigurationExactDirectories(s.publications, s.closed) != nil || len(s.closed) >= 128 || s.beforeCurrent(ctx) != nil || w.current(ctx) != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	id := seed.Operation.RequestID
	if createStreamRootPrivateDirectory(s.publications, id) != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	pub, err := s.publications.OpenRoot(id)
	if err != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	before, err := pub.Stat(".")
	current := func() bool {
		if !streamInstalledFixedRootCurrent(s.publications, loadBalanceStreamConfigurationPublicationsRoot) {
			return false
		}
		held, e1 := pub.Stat(".")
		named, e2 := s.publications.Lstat(id)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && memcachedUnixAdminDirectoryInfo(named) && os.SameFile(before, held) && os.SameFile(held, named)
	}
	if err != nil || !current() || s.beforeCurrent(ctx) != nil || w.current(ctx) != nil {
		pub.Close()
		return nil, loadbalancestream.ErrRuntime
	}
	p, err := stageLoadBalanceStreamOwnedConfigurationAt(ctx, w, pub, current, s.file)
	if err != nil {
		pub.Close()
		return nil, err
	}
	p.ownsPublication = true
	p.store = s
	return p, nil
}
