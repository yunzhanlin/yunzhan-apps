//go:build linux

package executor

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Private read-only kernel prerequisite for the fixed account child.
// A Root caller, a matching JSON permit or a same-named unit cannot create an
// account through this observer. The actual worker additionally requires its
// original held permit, Core/signature/cohort, runtime leases and create-once store.
func checkLoadBalanceStreamAccountChildKernel(ctx context.Context, parent *loadBalanceStreamAccountParent) error {
	if ctx == nil || ctx.Err() != nil || parent == nil || os.Getuid() != 0 || os.Getgid() != 0 || os.Geteuid() != 0 || os.Getegid() != 0 {
		return errLoadBalanceStreamAccount
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if parent.current(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	p := parent.permit
	child, err := loadbalancestream.AccountCreationUnit(p.JobID)
	if err != nil || uint32(os.Getpid()) == p.ParentPID {
		return errLoadBalanceStreamAccount
	}
	start, e1 := moduleProcessStart("/proc", os.Getpid())
	status, e2 := streamAccountParentProc("/proc/self/status", 65536)
	cgroup, e3 := streamAccountParentProc("/proc/self/cgroup", 4096)
	if e1 != nil || e2 != nil || e3 != nil || start == 0 || !streamAccountParentRootStatus(status) || string(cgroup) != "0::/system.slice/"+child+"\n" || threatIDSTrustedParents("/usr/bin", false) != nil {
		return errLoadBalanceStreamAccount
	}
	before, err := os.Lstat("/usr/bin/systemctl")
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 || before.Mode().Perm()&0022 != 0 {
		return errLoadBalanceStreamAccount
	}
	s, ok := before.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 {
		return errLoadBalanceStreamAccount
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", child, "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NoNewPrivileges,Slice,Type,BindsTo,After,KillMode,RemainAfterExit")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out, stderr := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, stderr, time.Second
	if cmd.Run() != nil || stderr.String() != "" || ctx.Err() != nil || !streamAccountChildUnitState([]byte(out.String()), p, uint32(os.Getpid())) {
		return errLoadBalanceStreamAccount
	}
	after, err := os.Lstat("/usr/bin/systemctl")
	endStart, endErr := moduleProcessStart("/proc", os.Getpid())
	endStatus, statusErr := streamAccountParentProc("/proc/self/status", 65536)
	endCgroup, groupErr := streamAccountParentProc("/proc/self/cgroup", 4096)
	if err != nil || endErr != nil || statusErr != nil || groupErr != nil || start != endStart || !streamAccountParentRootStatus(endStatus) ||
		string(endCgroup) != string(cgroup) || !geoStoreStableInfo(before, after) || parent.current(ctx) != nil || ctx.Err() != nil {
		return errLoadBalanceStreamAccount
	}
	return nil
}
