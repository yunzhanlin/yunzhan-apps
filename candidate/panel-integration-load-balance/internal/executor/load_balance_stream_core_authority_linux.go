//go:build linux

package executor

import (
	"context"
	"errors"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

var errLoadBalanceStreamCoreAuthority = errors.New("TCP/UDP 原始已派发请求、当前完整管理员修订或独立安装绑定无法核对；未授权本机变更")

// Share only the existing fixed-path, held-inode, live-WAL, SELECT-only Core
// descriptor implementation. No Memcached schema, operation, grant or mutable
// account semantics are borrowed or widened by this independent namespace.
type loadBalanceStreamCoreAuthority struct{ source *memcachedUpdateCoreAuthority }

func openLoadBalanceStreamCoreAuthority(ctx context.Context) (*loadBalanceStreamCoreAuthority, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	source, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	return &loadBalanceStreamCoreAuthority{source: source}, nil
}

func (r *loadBalanceStreamCoreAuthority) close() {
	if r != nil && r.source != nil {
		r.source.Close()
	}
}

// ONE prerequisite, not effect authority. The original Root run inode/runtime
// leases, actual signed installed module, programme floor, fixed identity and
// service/kernel/network/configuration proofs must ALSO hold before effects.
func (r *loadBalanceStreamCoreAuthority) check(ctx context.Context, op loadbalancestream.Operation, expected loadbalancestream.OperationBinding) error {
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil {
		return errLoadBalanceStreamCoreAuthority
	}
	raw, err := loadbalancestream.OperationBindingBytes(expected)
	if err != nil {
		return errLoadBalanceStreamCoreAuthority
	}
	if _, err = loadbalancestream.DecodeOperationBinding(raw, op); err != nil {
		return errLoadBalanceStreamCoreAuthority
	}
	authority, err := r.controlAuthority(ctx, op)
	if err != nil || authority.Format != 1 || authority.RequestID != op.RequestID || authority.ActorID != op.ActorID || authority.OperationSHA256 != expected.OperationSHA256 || authority.AppID != expected.AppID || authority.AppVersion != expected.AppVersion || authority.ManifestSHA256 != expected.ManifestSHA256 || authority.ActorObservationSHA256 != expected.ActorObservationSHA || authority.OriginalRequestSHA256 != expected.OriginalRequestSHA256 || authority.AccessRevision < 1 || ctx.Err() != nil {
		return errLoadBalanceStreamCoreAuthority
	}
	return nil
}

// First SELECT-only observation for constructing the separate traffic
// controller's binding. It is not an effect grant and accepts no Core path,
// claimed actor revision, installed hash or arbitrary DB connection from RPC.
// The controller must independently bind the actual installed Root instance,
// original on-disk generation, signed metadata and real native leases.
func (r *loadBalanceStreamCoreAuthority) controlAuthority(ctx context.Context, op loadbalancestream.Operation) (core.LoadBalanceStreamAuthority, error) {
	var empty core.LoadBalanceStreamAuthority
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	if _, err := loadbalancestream.OperationBytes(op); err != nil {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	source := r.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.db == nil || source.blocked == nil || source.blocked() || !source.current() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	v, err := (&core.Store{DB: source.db}).LoadBalanceStreamControlAuthority(ctx, op)
	if err != nil || v.Format != 1 || v.RequestID != op.RequestID || v.ActorID != op.ActorID || v.AppID != "load-balance" || v.AppVersion != loadbalancestream.AppVersion || v.OperationSHA256 != loadbalancestream.OperationSHA256(op) || !loadBalanceStreamAccountHash(v.ManifestSHA256) || !loadBalanceStreamAccountHash(v.ActorObservationSHA256) || v.AccessRevision < 1 || ctx.Err() != nil || !source.current() || source.blocked() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	return v, nil
}

// First read is a snapshot, NEVER permission to create an account or service.
// It must be bound to the selected independently verified signed metadata and
// original Root journal/lease before the fixed installer can perform effects.
func (r *loadBalanceStreamCoreAuthority) installAuthority(ctx context.Context, job string) (core.LoadBalanceStreamInstallAuthority, error) {
	var empty core.LoadBalanceStreamInstallAuthority
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil || !core.ValidID(job) {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	source := r.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.db == nil || source.blocked == nil || source.blocked() || !source.current() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	v, err := (&core.Store{DB: source.db}).LoadBalanceStreamInstallAuthority(ctx, job)
	if err != nil || v.Format != 1 || v.JobID != job || v.AppVersion != loadbalancestream.AppVersion || ctx.Err() != nil || !source.current() || source.blocked() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	return v, nil
}

func (r *loadBalanceStreamCoreAuthority) checkInstall(ctx context.Context, expected core.LoadBalanceStreamInstallAuthority) error {
	v, err := r.installAuthority(ctx, expected.JobID)
	if err != nil || v != expected {
		return errLoadBalanceStreamCoreAuthority
	}
	return nil
}

func (r *loadBalanceStreamCoreAuthority) controlCompletion(ctx context.Context, op loadbalancestream.Operation) (core.LoadBalanceStreamControlCompletion, error) {
	var empty core.LoadBalanceStreamControlCompletion
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	source := r.source
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.db == nil || source.blocked == nil || source.blocked() || !source.current() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	v, err := (&core.Store{DB: source.db}).LoadBalanceStreamControlCompletion(ctx, op)
	if err != nil || ctx.Err() != nil || !source.current() || source.blocked() {
		return empty, errLoadBalanceStreamCoreAuthority
	}
	return v, nil
}

func (r *loadBalanceStreamCoreAuthority) controlUpgradeHistory(ctx context.Context, original *core.LoadBalanceStreamAuthority) ([]core.LoadBalanceStreamControlUpgradeRecord, error) {
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	s := r.source
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil || s.blocked == nil || s.blocked() || !s.current() {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	v, err := (&core.Store{DB: s.db}).LoadBalanceStreamControlUpgradeHistory(ctx, original)
	if err != nil || ctx.Err() != nil || !s.current() || s.blocked() {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	return v, nil
}
