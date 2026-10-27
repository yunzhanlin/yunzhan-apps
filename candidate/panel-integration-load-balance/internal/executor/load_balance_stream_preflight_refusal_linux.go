//go:build linux

package executor

import (
	"context"
	"os"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamPreflightRefusalError struct {
	result core.LoadBalanceStreamNativeResult
}

func (*loadBalanceStreamPreflightRefusalError) Error() string {
	return "TCP/UDP original preflight refused before control effects"
}

// Only the fresh original preparer can acknowledge a read-only preflight
// rejection. Revalidate live authority, installation, held leases, fixed
// executor MainPID/start time and its kernel FLOCK owner; no caller-supplied
// flag, stale seed, foreign process or reader can manufacture this state.
func (c *loadBalanceStreamTrafficController) refuseBeforeEffects(ctx context.Context, service *Service, op loadbalancestream.Operation, grant core.LoadBalanceStreamAuthority, stage string) (*loadBalanceStreamTrafficController, error) {
	defer c.close()
	bad := errLoadBalanceStreamInstallationGate
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || c == nil || c.effectsStarted ||
		service == nil || service.Config.SystemRoot != "/" || service.Config.SecurityDir != "/etc/panel/security-apps" ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) || c.source == nil || c.installed == nil ||
		c.store == nil || c.lifetime == nil || c.lifetime.file.file == nil || c.mutation == nil ||
		c.journal != nil || c.owner != nil || c.config != nil || c.running != nil || c.stopped != nil || len(c.generationRaw) != 0 ||
		!c.lifetime.current() || !c.mutation.current() || !streamControlHeldLease(c.lifetime.file.file, false) || !streamControlHeldLease(c.mutation.file, true) ||
		c.installed.current(ctx) != nil || c.store.beforeCurrent(ctx) != nil {
		return nil, bad
	}
	current, err := c.source.controlAuthority(ctx, op)
	if err != nil || current != grant || c.store.original != grant || loadbalancestream.OperationSHA256(c.store.operation) != grant.OperationSHA256 {
		return nil, bad
	}
	process, err := currentModuleApplyOwner()
	if err != nil || service.authorizeModuleCandidate(ctx, loadBalanceStreamMutationLockPath, process) != nil {
		return nil, bad
	}
	current, err = c.source.controlAuthority(ctx, op)
	if err != nil || current != grant || ctx.Err() != nil || c.installed.current(ctx) != nil || c.store.beforeCurrent(ctx) != nil ||
		!c.lifetime.current() || !c.mutation.current() || !streamControlHeldLease(c.lifetime.file.file, false) || !streamControlHeldLease(c.mutation.file, true) {
		return nil, bad
	}
	result := streamControlResult(op, "refused-before-effects")
	result.Preflight = &core.LoadBalanceStreamPreflightRefusal{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
		OperationSHA256: grant.OperationSHA256, ManifestSHA256: grant.ManifestSHA256,
		InstalledSHA256: core.Hash(string(c.installed.installed.raw)), ProgrammeInputsSHA256: loadBalanceStreamCompiledProgrammeInputsSHA256,
		ActorObservationSHA256: grant.ActorObservationSHA256, OriginalRequestSHA256: grant.OriginalRequestSHA256, Stage: stage}
	if core.ValidateLoadBalanceStreamNativeResult(result, op) != nil {
		return nil, bad
	}
	return nil, &loadBalanceStreamPreflightRefusalError{result: result}
}
