//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

var errLoadBalanceStreamInstallationGate = errors.New("TCP/UDP 原始安装日志、完整管理员修订或独立签名发行绑定不一致；未授权系统变更")

// This held prerequisite joins real SELECT-only Core authority, the original
// creator's leased private journal and independently compiled-key verification.
// The fixed original installer must ALSO hold its
// global native/runtime leases and validate platform, owned identity and actual
// programme-input/service/kernel/configuration state. The caller serializes
// journal mutation and checks under the same original controller lease; this
// observer provides no global/effect serialization and never performs effects.
type loadBalanceStreamInstallationGate struct {
	journal  *loadBalanceStreamInstallationJournal
	source   *loadBalanceStreamCoreAuthority
	original core.LoadBalanceStreamInstallAuthority
	seed     []byte
}

func bindLoadBalanceStreamInstallationGate(ctx context.Context, j *loadBalanceStreamInstallationJournal, r *loadBalanceStreamCoreAuthority) (*loadBalanceStreamInstallationGate, error) {
	if ctx == nil || ctx.Err() != nil || j == nil || r == nil || !j.creator || j.unknown {
		return nil, errLoadBalanceStreamInstallationGate
	}
	raw, records, chain, err := j.original(ctx)
	if err != nil || len(records) != 1 || chain.Complete || !chain.OriginalUnknown {
		return nil, errLoadBalanceStreamInstallationGate
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(raw)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	original, err := r.installAuthority(ctx, seed.JobID)
	if err != nil || !loadBalanceStreamInstallationGrantMatches(raw, original) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	gate := &loadBalanceStreamInstallationGate{journal: j, source: r, original: original, seed: bytes.Clone(raw)}
	if gate.current(ctx) != nil {
		clear(gate.seed)
		return nil, errLoadBalanceStreamInstallationGate
	}
	after, afterRecords, _, err := j.original(ctx)
	if err != nil || len(afterRecords) != 1 || !bytes.Equal(after, raw) || !bytes.Equal(afterRecords[0], records[0]) {
		clear(gate.seed)
		return nil, errLoadBalanceStreamInstallationGate
	}
	return gate, nil
}

// Re-check before each proposed effect. Old openers, completed/unknown journals,
// swapped original inodes, revoked/reissued Core grants, a changed signed
// envelope or a changed canonical seed are never recovered or adopted here.
func (g *loadBalanceStreamInstallationGate) current(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil || g.journal == nil || g.source == nil ||
		!g.journal.creator || g.journal.unknown || len(g.seed) == 0 {
		return errLoadBalanceStreamInstallationGate
	}
	raw, records, chain, err := g.journal.original(ctx)
	if err != nil || len(records) < 1 || len(records) >= loadbalancestream.InstallationPhaseCount ||
		chain.Complete || !chain.OriginalUnknown || !bytes.Equal(raw, g.seed) ||
		!loadBalanceStreamInstallationGrantMatches(raw, g.original) ||
		g.source.checkInstall(ctx, g.original) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if _, err := g.journal.officialAuthority(ctx); err != nil {
		return errLoadBalanceStreamInstallationGate
	}
	after, afterRecords, afterChain, err := g.journal.original(ctx)
	if err != nil || afterChain.Complete || !afterChain.OriginalUnknown || !bytes.Equal(after, g.seed) ||
		len(afterRecords) != len(records) || !g.journal.creator || g.journal.unknown || ctx.Err() != nil || g.source.checkInstall(ctx, g.original) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	for i := range records {
		if !bytes.Equal(records[i], afterRecords[i]) {
			return errLoadBalanceStreamInstallationGate
		}
	}
	return nil
}
