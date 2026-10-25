//go:build linux

package executor

import (
	"context"

	"local/panel/internal/core"
)

// Independent Unix namespace. Neither method broadens compat2's verifier,
// update/restoration journal, or original mutable TCP worker. A binding is
// identity data, not a compiled-key signature, Docker inspection or run lease.
func (r *memcachedUpdateCoreAuthority) unixInstall(ctx context.Context, op core.DockerProjectRequest, expected core.MemcachedUnixBinding) error {
	if r == nil {
		return errMemcachedCoreAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.db == nil || r.blocked == nil || r.blocked() || !r.current() {
		return errMemcachedCoreAuthority
	}
	store := &core.Store{DB: r.db}
	bound, err := store.MemcachedUnixInstallBinding(ctx, op)
	if err != nil || bound != expected || !r.current() || r.blocked() || ctx.Err() != nil {
		return errMemcachedCoreAuthority
	}
	return nil
}

func (r *memcachedUpdateCoreAuthority) unixOperation(ctx context.Context, actor string, original core.DockerProjectRequest, action string, expected core.MemcachedUnixBinding) error {
	if r == nil {
		return errMemcachedCoreAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.db == nil || r.blocked == nil || r.blocked() || !r.current() {
		return errMemcachedCoreAuthority
	}
	store := &core.Store{DB: r.db}
	bound, err := store.MemcachedUnixOperationBinding(ctx, actor, original, action)
	if err != nil || bound != expected || !r.current() || r.blocked() || ctx.Err() != nil {
		return errMemcachedCoreAuthority
	}
	return nil
}
