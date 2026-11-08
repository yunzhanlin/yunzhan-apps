//go:build linux

package executor

import (
	"bytes"
	"context"
	"path/filepath"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// One live authorization PREREQUISITE, never a replacement for actual held
// runtime/configuration leases, original generation, kernel/resource/port
// occupancy or the independently measured original native service identity.
type loadBalanceStreamControlGate struct {
	journal   *loadBalanceStreamJournal
	installed *loadBalanceStreamInstalledContext
	source    *loadBalanceStreamCoreAuthority
	original  core.LoadBalanceStreamAuthority
	seed      []byte
}

func (g *loadBalanceStreamControlGate) close() {
	if g != nil {
		clear(g.seed)
		g.seed = nil
	}
}

func bindLoadBalanceStreamControlGate(ctx context.Context, j *loadBalanceStreamJournal, installed *loadBalanceStreamInstalledContext, source *loadBalanceStreamCoreAuthority) (*loadBalanceStreamControlGate, error) {
	if ctx == nil || ctx.Err() != nil || j == nil || !j.creator || j.unknown || installed == nil || source == nil || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	raw, records, chain, err := j.original(ctx)
	if err != nil || len(records) != 1 || chain.Complete || !chain.OriginalUnknown {
		return nil, errLoadBalanceStreamInstallationGate
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || j.path != filepath.Join(loadBalanceStreamJobsRoot, seed.Operation.RequestID) || seed.Binding.ProgrammeInputs != loadBalanceStreamCompiledProgrammeInputsSHA256 || installed.current(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	original, err := source.controlAuthority(ctx, seed.Operation)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	g := &loadBalanceStreamControlGate{journal: j, installed: installed, source: source, original: original, seed: bytes.Clone(raw)}
	if g.current(ctx) != nil {
		g.close()
		return nil, errLoadBalanceStreamInstallationGate
	}
	return g, nil
}

func (g *loadBalanceStreamControlGate) current(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil || g.journal == nil || !g.journal.creator || g.journal.unknown || g.journal.lock == nil || g.installed == nil || g.source == nil || len(g.seed) == 0 || g.installed.current(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	raw, records, chain, err := g.journal.original(ctx)
	if err != nil || len(records) < 1 || len(records) >= 12 || chain.Complete || !chain.OriginalUnknown || !bytes.Equal(raw, g.seed) {
		return errLoadBalanceStreamInstallationGate
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || g.journal.path != filepath.Join(loadBalanceStreamJobsRoot, seed.Operation.RequestID) || seed.Binding.ProgrammeInputs != loadBalanceStreamCompiledProgrammeInputsSHA256 || seed.Binding.InstalledSHA256 != core.Hash(string(g.installed.installed.raw)) {
		return errLoadBalanceStreamInstallationGate
	}
	install, err := loadbalancestream.DecodeInstallationSeed(g.installed.seedRaw)
	if err != nil || seed.Binding.ManifestSHA256 != install.ManifestSHA256 || seed.Binding.ManifestSHA256 != g.original.ManifestSHA256 || seed.Binding.ActorObservationSHA != g.original.ActorObservationSHA256 || seed.Binding.OperationSHA256 != g.original.OperationSHA256 {
		return errLoadBalanceStreamInstallationGate
	}
	original, err := g.source.controlAuthority(ctx, seed.Operation)
	if err != nil || original != g.original || g.source.check(ctx, seed.Operation, seed.Binding) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if !g.journal.current() || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}
