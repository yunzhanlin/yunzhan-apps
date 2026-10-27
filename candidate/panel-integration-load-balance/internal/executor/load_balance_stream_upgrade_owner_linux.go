//go:build linux

package executor

import (
	"context"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Private concrete live witnesses, NOT caller-selected unit/job exclusions.
// No RPC, environment, recovery opener or CLI can provide this object. Each
// census checks it again before and after reading Core, files and systemd.
type loadBalanceStreamUpgradeOwner struct {
	source     *loadBalanceStreamCoreAuthority
	original   core.LoadBalanceStreamInstallAuthority
	lifetime   *memcachedUnixRuntimeLease
	mutation   *loadBalanceStreamMutationLease
	submission *loadBalanceStreamHeldSubmission
	parent     *loadBalanceStreamInstallController
	child      *loadBalanceStreamAccountParent
	compose    *dockerMutationLease
}

func (o *loadBalanceStreamUpgradeOwner) current(ctx context.Context) error {
	if o == nil || ctx == nil || ctx.Err() != nil || o.source == nil || o.lifetime == nil || !o.lifetime.current() ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) || o.source.checkInstall(ctx, o.original) != nil ||
		os.Getuid() != 0 || os.Geteuid() != 0 {
		return errLoadBalanceStreamInstallationGate
	}
	if o.child != nil {
		if o.parent != nil || o.mutation != nil || o.submission != nil || o.compose == nil || !o.compose.currentLocked() ||
			o.child.permit.JobID != o.original.JobID || o.child.permitRecord == nil || !o.child.permitRecord.current() ||
			!loadBalanceStreamProgrammeInputsMatch(loadBalanceStreamCompiledProgrammeInputsSHA256, o.child.permit.ProgrammeInputsSHA256) ||
			checkLoadBalanceStreamAccountChildKernel(ctx, o.child) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		return nil
	}
	if o.compose != nil || o.mutation == nil || !o.mutation.current() {
		return errLoadBalanceStreamInstallationGate
	}
	if o.parent != nil {
		w := o.parent
		if w.source != o.source || w.lifetime != o.lifetime || w.mutation != o.mutation || w.submission == nil || !w.submission.current() ||
			w.submission.value.JobID != o.original.JobID || checkLoadBalanceStreamInstallParentKernel(ctx, o.original.JobID) != nil ||
			w.gate != nil && w.current(ctx) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		return nil
	}
	// Original RPC dispatcher, before its single parent start, holds both real
	// leases. An optional handoff MUST be this new writer, not an old opener.
	if o.submission != nil && (!o.submission.creator || !o.submission.current() || o.submission.value.JobID != o.original.JobID) {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}

func (o *loadBalanceStreamUpgradeOwner) activeUnits(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	if o == nil {
		return out, nil
	}
	if o.current(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	if o.parent != nil || o.child != nil {
		unit, err := loadbalancestream.AccountParentUnit(o.original.JobID)
		if err != nil {
			return nil, err
		}
		out[unit] = true
	}
	if o.child != nil {
		unit, err := loadbalancestream.AccountCreationUnit(o.original.JobID)
		if err != nil {
			return nil, err
		}
		out[unit] = true
	}
	return out, nil
}

func streamUpgradeUnitName(name string) bool {
	for _, prefix := range []string{"panel-lbstream-install@", "panel-lbstream-account-create@"} {
		if id, ok := strings.CutPrefix(name, prefix); ok {
			job, suffix := strings.CutSuffix(id, ".service")
			return suffix && core.ValidID(job)
		}
	}
	return false
}

func streamUpgradeUnitPrefix(name string) bool {
	return strings.HasPrefix(name, "panel-lbstream-install@") || strings.HasPrefix(name, "panel-lbstream-account-create@")
}

// Pure parser seam only. Production's active set comes exclusively from the
// concrete held kernel/lease/Core witness above, not from user JSON or names.
func decodeLoadBalanceStreamUpgradeUnits(text string, active map[string]bool) error {
	if len(text) > 64<<10 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return errLoadBalanceStreamInstallationGate
	}
	seen, live := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v := strings.Fields(line)
		if len(v) < 4 || len(seen) >= 256 || !streamUpgradeUnitName(v[0]) || seen[v[0]] || v[1] != "loaded" {
			return errLoadBalanceStreamInstallationGate
		}
		seen[v[0]] = true
		if v[2] == "inactive" && v[3] == "dead" {
			continue
		}
		if !active[v[0]] || v[2] != "active" || v[3] != "running" {
			return errLoadBalanceStreamInstallationGate
		}
		live[v[0]] = true
	}
	for unit, yes := range active {
		if !yes || !streamUpgradeUnitName(unit) || !live[unit] {
			return errLoadBalanceStreamInstallationGate
		}
	}
	return nil
}

func decodeLoadBalanceStreamUpgradeJobs(text string) error {
	if len(text) > 64<<10 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return errLoadBalanceStreamInstallationGate
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v := strings.Fields(line)
		if len(v) != 4 || len(seen) >= 2048 {
			return errLoadBalanceStreamInstallationGate
		}
		n, err := strconv.ParseUint(v[0], 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != v[0] || seen[v[0]] || streamUpgradeUnitPrefix(v[1]) {
			return errLoadBalanceStreamInstallationGate
		}
		seen[v[0]] = true
	}
	return nil
}

func checkLoadBalanceStreamNativeQueues(ctx context.Context, owner *loadBalanceStreamUpgradeOwner) error {
	active, err := owner.activeUnits(ctx)
	if err != nil {
		return err
	}
	units, err := programQueueCommand(ctx, "/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager", "--type=service", "panel-lbstream-install@*.service", "panel-lbstream-account-create@*.service")
	if err != nil || decodeLoadBalanceStreamUpgradeUnits(units, active) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	jobs, err := programQueueCommand(ctx, "/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager")
	// Even an own start job is NOT broadly exempted. Type=exec's completed
	// activation must already have drained before this controller may act.
	if err != nil || decodeLoadBalanceStreamUpgradeJobs(jobs) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	if owner != nil {
		return owner.current(ctx)
	}
	return ctx.Err()
}
