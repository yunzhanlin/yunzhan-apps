//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Private, read-only kernel witness, NOT effect authority. The future fixed
// child additionally checks its OWN fixed unit, current Core/signed grant,
// original programme inputs, global leases and exclusive durable attempt.
// It must be BindsTo/After the original parent; this snapshot does not promise
// parent continuity between observations and never creates an account.
type loadBalanceStreamAccountParent struct {
	permit     loadbalancestream.AccountChildPermit
	j          *loadBalanceStreamInstallationJournal
	pidfd      int
	fdName     string
	executable *loadBalanceStreamAccountExecutable
	// Set only by the fixed production child after opening its original
	// private permit. Kernel-only component witnesses deliberately lack it.
	permitRecord *loadBalanceStreamHeldAccountPermit
}

func streamAccountParentProc(name string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errLoadBalanceStreamAccount
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errLoadBalanceStreamAccount
	}
	return raw, nil
}

func (w *loadBalanceStreamAccountParent) Close() {
	if w != nil {
		w.executable.close()
		w.executable = nil
	}
	if w != nil && w.pidfd >= 0 {
		unix.Close(w.pidfd)
		w.pidfd = -1
	}
}

func (w *loadBalanceStreamAccountParent) live() bool {
	if w == nil || w.pidfd < 0 {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(w.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	return err == nil && n == 0 && poll[0].Revents == 0
}

func streamAccountParentLockInfo(info os.FileInfo, p loadbalancestream.AccountChildPermit) bool {
	if info == nil || info.Mode() != 0600 || info.Size() != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && s.Gid == 0 && s.Nlink == 1 && uint64(s.Dev) == p.RunLockDevice && s.Ino == p.RunLockInode
}

func (w *loadBalanceStreamAccountParent) descriptor(ctx context.Context, name string) bool {
	if ctx.Err() != nil || !w.live() {
		return false
	}
	proc := "/proc/" + strconv.FormatUint(uint64(w.permit.ParentPID), 10)
	// Intentional procfs magic-link metadata lookup, never a caller file path.
	a, err := os.Stat(proc + "/fd/" + name)
	if err != nil || !streamAccountParentLockInfo(a, w.permit) {
		return false
	}
	raw, err := streamAccountParentProc(proc+"/fdinfo/"+name, 8192)
	b, afterErr := os.Stat(proc + "/fd/" + name)
	return err == nil && afterErr == nil && geoStoreStableInfo(a, b) && streamAccountParentLockInfo(b, w.permit) &&
		streamAccountParentFDInfo(raw, w.permit, unix.Major(w.permit.RunLockDevice), unix.Minor(w.permit.RunLockDevice)) && w.live() && ctx.Err() == nil
}

func (w *loadBalanceStreamAccountParent) unit(ctx context.Context) bool {
	unit, err := loadbalancestream.AccountParentUnit(w.permit.JobID)
	if err != nil || threatIDSTrustedParents("/usr/bin", false) != nil {
		return false
	}
	before, err := os.Lstat("/usr/bin/systemctl")
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 || before.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 {
		return false
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NoNewPrivileges,Slice")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, stderr := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, stderr, time.Second
	if cmd.Run() != nil || stderr.String() != "" || ctx.Err() != nil {
		return false
	}
	after, err := os.Lstat("/usr/bin/systemctl")
	return err == nil && geoStoreStableInfo(before, after) && streamAccountParentUnitState([]byte(output.String()), w.permit)
}

func (w *loadBalanceStreamAccountParent) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || w.j == nil || !w.live() {
		return errLoadBalanceStreamAccount
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	p := w.permit
	if _, err := loadbalancestream.AccountChildPermitBytes(p); err != nil || w.j.path != filepath.Join(loadBalanceStreamInstallationJobsRoot, p.JobID) {
		return errLoadBalanceStreamAccount
	}
	raw, records, _, err := w.j.original(ctx)
	if err != nil || len(records) != 2 || !loadbalancestream.AccountChildPermitBindsSeed(p, raw) || core.Hash(string(records[1])) != p.AccountIntentSHA256 {
		return errLoadBalanceStreamAccount
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(raw)
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	directory, err := w.j.root.Stat(".")
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	ds, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || uint64(ds.Dev) != p.JournalDevice || ds.Ino != p.JournalInode {
		return errLoadBalanceStreamAccount
	}
	lock, err := w.j.read("run.lock", 0)
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	defer lock.close()
	if !streamAccountParentLockInfo(lock.before, p) || !w.descriptor(ctx, w.fdName) {
		return errLoadBalanceStreamAccount
	}
	proc := "/proc/" + strconv.FormatUint(uint64(p.ParentPID), 10)
	boot, e1 := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	status, e2 := streamAccountParentProc(proc+"/status", 65536)
	cgroup, e3 := streamAccountParentProc(proc+"/cgroup", 4096)
	parent, _ := loadbalancestream.AccountParentUnit(p.JobID)
	child, _ := loadbalancestream.AccountCreationUnit(p.JobID)
	group := "/system.slice/" + parent
	start, e4 := moduleProcessStart("/proc", int(p.ParentPID))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || string(boot) != p.BootID+"\n" || !streamAccountParentRootStatus(status) || string(cgroup) != "0::"+group+"\n" || start != p.ParentStartTicks || !w.unit(ctx) {
		return errLoadBalanceStreamAccount
	}
	// The held same-programme inode was fully hashed at acquisition. Recheck
	// actual procfs identities and all original metadata on EVERY observation.
	if !w.executable.current(ctx, p.ParentPID, p.ParentExeSHA256) {
		return errLoadBalanceStreamAccount
	}
	o := loadbalancestream.AccountParentObservation{BootID: string(boot[:len(boot)-1]), PID: p.ParentPID, StartTicks: start, ExeSHA256: w.executable.sha256, ProgrammeInputsSHA256: seed.ProgrammeInputsSHA256, SeedSHA256: core.Hash(string(raw)), AccountIntentSHA256: core.Hash(string(records[1])), Unit: parent, ChildUnit: child, ControlGroup: group, ProcessControlGroup: group, NoNewPrivileges: true, ActiveRunning: true, ExclusiveRunLock: true, RunLockReadWrite: true, RunLockOrdinary: true, RunLockOwnerPID: p.ParentPID, JournalDevice: uint64(ds.Dev), JournalInode: ds.Ino, RunLockDevice: p.RunLockDevice, RunLockInode: p.RunLockInode, RunLockMode: 0600, RunLockLinks: 1, JournalPhase: "account-intent"}
	endStart, err := moduleProcessStart("/proc", int(p.ParentPID))
	if err != nil || endStart != start || !loadbalancestream.AccountChildParentMatches(p, o, time.Now()) || !lock.current() || !w.j.current() || !w.descriptor(ctx, w.fdName) || !w.executable.current(ctx, p.ParentPID, p.ParentExeSHA256) || ctx.Err() != nil {
		return errLoadBalanceStreamAccount
	}
	return nil
}

func holdLoadBalanceStreamAccountParent(ctx context.Context, p loadbalancestream.AccountChildPermit, j *loadBalanceStreamInstallationJournal) (*loadBalanceStreamAccountParent, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || p.ParentPID == uint32(os.Getpid()) || j == nil {
		return nil, errLoadBalanceStreamAccount
	}
	if _, err := loadbalancestream.AccountChildPermitBytes(p); err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	pidfd, err := unix.PidfdOpen(int(p.ParentPID), 0)
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	w := &loadBalanceStreamAccountParent{permit: p, j: j, pidfd: pidfd}
	dir, err := os.Open("/proc/" + strconv.FormatUint(uint64(p.ParentPID), 10) + "/fd")
	if err != nil {
		w.Close()
		return nil, errLoadBalanceStreamAccount
	}
	defer dir.Close()
	var fs unix.Statfs_t
	entries, err := dir.ReadDir(257)
	if err != nil && err != io.EOF || len(entries) > 256 || unix.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		w.Close()
		return nil, errLoadBalanceStreamAccount
	}
	for _, entry := range entries {
		n, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != entry.Name() {
			w.Close()
			return nil, errLoadBalanceStreamAccount
		}
		if w.descriptor(ctx, entry.Name()) {
			if w.fdName != "" { // Ambiguous aliases are not original ownership.
				w.Close()
				return nil, errLoadBalanceStreamAccount
			}
			w.fdName = entry.Name()
		}
	}
	if w.fdName == "" {
		w.Close()
		return nil, errLoadBalanceStreamAccount
	}
	w.executable, err = holdLoadBalanceStreamAccountExecutable(ctx, p.ParentPID)
	if err != nil || w.current(ctx) != nil {
		w.Close()
		return nil, errLoadBalanceStreamAccount
	}
	return w, nil
}
