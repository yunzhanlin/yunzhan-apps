//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

// Bounded shared lifetime only; deliberately NO parent engine lease while a
// dedicated account child acquires its own. Use the original held/name/inode
// validator and never create/repair the lifecycle lock.
type memcachedUnixRuntimeLease struct {
	tree *dockerMutationTree
	file dockerMutationHeldFile
}

func acquireMemcachedUnixRuntime(ctx context.Context) (*memcachedUnixRuntimeLease, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errDockerMutation
	}
	tree, err := openDockerMutationTree("/var/lib/panel-executor")
	if err != nil {
		return nil, err
	}
	file, err := dockerMutationFile(tree.roots[len(tree.roots)-2], "runtime-lifecycle.lock", false)
	if err != nil {
		tree.close()
		return nil, err
	}
	if dockerMutationFlock(ctx, file, unix.LOCK_SH) != nil || !tree.current() {
		file.file.Close()
		tree.close()
		return nil, errDockerMutation
	}
	return &memcachedUnixRuntimeLease{tree: tree, file: file}, nil
}
func (l *memcachedUnixRuntimeLease) Close() {
	if l != nil && l.tree != nil {
		l.file.file.Close()
		l.tree.close()
		l.tree = nil
	}
}
func (l *memcachedUnixRuntimeLease) current() bool {
	return l != nil && l.tree != nil && l.tree.current() && l.file.current()
}

// Native-only witness. A job ID or canonical record cannot manufacture it:
// the actual fixed executor MainPID/start/executable must still own the exact
// Root journal run inode. The dependency child does not inherit/reacquire the
// parent's engine lease; it acquires its own only after these independent gates.
type memcachedUnixOriginalRun struct {
	j     *memcachedUnixJournal
	owner moduleApplyOwner
	s     *Service
}

func (j *memcachedUnixJournal) productionLocation() bool {
	return j != nil && j.d != nil && len(j.d.paths) >= 2 && j.d.paths[len(j.d.paths)-2] == memcachedUnixInstallJobsRoot && j.d.paths[len(j.d.paths)-1] == filepath.Join(memcachedUnixInstallJobsRoot, j.id)
}

func memcachedUnixFindOriginalRun(ctx context.Context, j *memcachedUnixJournal) (*memcachedUnixOriginalRun, error) {
	if ctx == nil || ctx.Err() != nil || j == nil || os.Geteuid() != 0 || !j.productionLocation() {
		return nil, errMemcachedUnixJournal
	}
	s := New(Config{})
	child, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := s.Config.Run(child, "/usr/bin/systemctl", "show", "panel-executor.service", "--property=MainPID", "--value")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parseErr != nil || pid <= 1 {
		return nil, errMemcachedUnixJournal
	}
	start, err := moduleProcessStart("/proc", pid)
	if err != nil {
		return nil, err
	}
	own := &memcachedUnixOriginalRun{j: j, owner: moduleApplyOwner{PID: pid, StartTime: start}, s: s}
	if own.current(ctx) != nil {
		return nil, errMemcachedUnixJournal
	}
	return own, nil
}

func (own *memcachedUnixOriginalRun) current(ctx context.Context) error {
	if own == nil || own.j == nil || own.s == nil || ctx == nil || ctx.Err() != nil || !own.j.current() || !own.j.productionLocation() {
		return errMemcachedUnixJournal
	}
	head, err := own.j.read()
	if err != nil || head.Operation.JobID != own.j.id || core.ValidateMemcachedUnixInstallRecord(head) != nil {
		return errMemcachedUnixJournal
	}
	if _, err := own.j.officialAuthority(ctx); err != nil {
		return err
	}
	lock := filepath.Join(memcachedUnixInstallJobsRoot, own.j.id, "run.lock")
	if own.s.authorizeModuleCandidate(ctx, lock, &own.owner) != nil {
		return errMemcachedUnixJournal
	}
	// Same installed executable as this independently launched fixed child;
	// a PID/name/label from an unrelated Root process is not the executor.
	parent, e1 := os.Stat(filepath.Join("/proc", strconv.Itoa(own.owner.PID), "exe"))
	self, e2 := os.Stat("/proc/self/exe")
	if e1 != nil || e2 != nil || !parent.Mode().IsRegular() || !os.SameFile(parent, self) {
		return errMemcachedUnixJournal
	}
	after, err := own.j.read()
	if err != nil || after != head || !own.j.current() || ctx.Err() != nil {
		return errMemcachedUnixJournal
	}
	return nil
}

func (own *memcachedUnixOriginalRun) otherTransactions(ctx context.Context) error {
	if own.current(ctx) != nil {
		return errMemcachedUnixJournal
	}
	if err := (memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}).checkTransactions(ctx, nil); err != nil {
		return err
	}
	if err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(ctx); err != nil {
		return err
	}
	if err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).checkOriginalTransactions(ctx, own); err != nil {
		return err
	}
	head, err := own.j.read()
	if err != nil {
		return err
	}
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := (&core.Store{DB: reader.db}).CheckMemcachedUnixControlUpgrade(ctx); err != nil {
		return err
	}
	if reader.unixInstall(ctx, head.Operation, head.Binding) != nil || (&core.Store{DB: reader.db}).CheckMemcachedUnixOtherInstalls(ctx, head.Operation, head.Binding) != nil || !reader.current() {
		return errMemcachedCoreAuthority
	}
	return own.current(ctx)
}
