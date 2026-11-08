//go:build linux

package executor

import (
	"bytes"
	"context"
	"path/filepath"
	"time"

	"local/panel/internal/loadbalancestream"
)

// The original live writer invokes precisely ONE fixed reviewed nginx -t
// through the system manager, under the service account and zero capabilities.
// This tests syntax only: it does not prove free ports, active listeners,
// forwarding, enforced egress, successful reload, boot recovery or health.
// nginx -t may create missing OWNED runtime temporary leaves. It is never
// described as read-only, and cannot authorize arbitrary paths or cleanup.
func (p *loadBalanceStreamConfigurationPublication) verifySyntaxOwned(ctx context.Context, w *loadBalanceStreamControlOwner) error {
	if p == nil || p.syntaxIssued || p.attempted || p.promoted || p.original == nil || p.original.root == nil || p.publication == nil || !p.metadataCurrent() || !p.original.current() || !p.candidateCurrent() {
		return loadbalancestream.ErrRuntime
	}
	raw, err := w.configurationPhase(ctx, "syntax-intent")
	if err != nil || !bytes.Equal(raw, p.seed) || p.original.root.Name() != loadBalanceStreamConfigurationRoot || p.publication.Name() != filepath.Join(loadBalanceStreamConfigurationPublicationsRoot, p.request) || p.original.gid != w.gate.installed.identity.GID {
		return loadbalancestream.ErrRuntime
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, w.gate.installed)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	facts.Validation.PanelControlPorts = ports
	// No port is bound by -t. Independent complete TCP/UDP occupancy/custom
	// control-port census remains mandatory BEFORE native activation.
	plan, err := loadbalancestream.PlanControlServiceLaunch(seed, facts, p.request)
	if err != nil || !bytes.Equal(plan.Service.Current.Main, p.proposal) {
		return loadbalancestream.ErrRuntime
	}
	unit := "panel-load-balance-stream-syntax@" + p.request + ".service"
	prior, err := streamInstallUnitProperties(ctx, unit)
	if err != nil || prior["LoadState"] != "not-found" || prior["ActiveState"] != "inactive" || prior["SubState"] != "dead" || prior["MainPID"] != "0" || prior["ControlPID"] != "0" || prior["InvocationID"] != "" {
		return loadbalancestream.ErrRuntime
	}
	if _, err := w.configurationPhase(ctx, "syntax-intent"); err != nil || !p.original.current() || !p.candidateCurrent() || !p.metadataCurrent() {
		return loadbalancestream.ErrRuntime
	}
	// Set before the only start call. A timeout/missing reply or lost original
	// object is unknown and cannot re-run this native unit or adopt its output.
	p.syntaxIssued = true
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	_, err = programQueueCommand(bounded, "/usr/bin/systemd-run", plan.Syntax...)
	cancel()
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	// --wait + Type=exec gives THIS start's actual command completion, not a
	// stale inactive snapshot. A transient unit may already be collected after
	// exit; no old unit/opened receipt is promoted into an original exit proof.
	if _, err := w.configurationPhase(ctx, "syntax-intent"); err != nil || !p.original.current() || !p.candidateCurrent() || !p.metadataCurrent() {
		return loadbalancestream.ErrRuntime
	}
	p.syntaxVerified = true
	return nil
}
