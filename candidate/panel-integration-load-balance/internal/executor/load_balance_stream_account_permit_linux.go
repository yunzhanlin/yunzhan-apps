//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamAccountPermitsRoot = "/var/lib/panel-executor/load-balance-stream-account-permits"

// A permit is only a retained description of the original parent. It grants
// nothing without the child's actual kernel witness, live Core revision,
// compiled programme cohort, official signature and independent runtime leases.
func observeLoadBalanceStreamAccountParent(ctx context.Context, g *loadBalanceStreamInstallationGate) (loadbalancestream.AccountChildPermit, error) {
	empty := loadbalancestream.AccountChildPermit{}
	if ctx == nil || ctx.Err() != nil || g == nil || g.journal == nil ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) || g.current(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	j := g.journal
	raw, records, _, err := j.original(ctx)
	if err != nil || len(records) != 2 {
		return empty, errLoadBalanceStreamAccount
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(raw)
	if err != nil || !loadBalanceStreamProgrammeInputsMatch(loadBalanceStreamCompiledProgrammeInputsSHA256, seed.ProgrammeInputsSHA256) ||
		j.path != filepath.Join(loadBalanceStreamInstallationJobsRoot, seed.JobID) || j.lock == nil {
		return empty, errLoadBalanceStreamAccount
	}
	directory, e1 := j.root.Stat(".")
	lock, e2 := j.lock.Stat()
	if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(directory) {
		return empty, errLoadBalanceStreamAccount
	}
	ds, ok := directory.Sys().(*syscall.Stat_t)
	ls, ok2 := lock.Sys().(*syscall.Stat_t)
	if !ok || !ok2 {
		return empty, errLoadBalanceStreamAccount
	}
	boot, e1 := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	start, e2 := moduleProcessStart("/proc", os.Getpid())
	if e1 != nil || e2 != nil || start == 0 || !strings.HasSuffix(string(boot), "\n") {
		return empty, errLoadBalanceStreamAccount
	}
	f, err := os.Open("/proc/self/exe") // Deliberate identity of this live ELF.
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer f.Close()
	a, err := f.Stat()
	if err != nil || !a.Mode().IsRegular() || a.Size() <= 0 || a.Size() > 128<<20 {
		return empty, errLoadBalanceStreamAccount
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1)); err != nil || n != a.Size() {
		return empty, errLoadBalanceStreamAccount
	}
	z, err := f.Stat()
	if err != nil || !geoStoreStableInfo(a, z) || ctx.Err() != nil {
		return empty, errLoadBalanceStreamAccount
	}
	p := loadbalancestream.AccountChildPermit{Format: 1, AppVersion: seed.AppVersion, JobID: seed.JobID, ActorID: seed.ActorID, Nonce: seed.Nonce,
		BootID: strings.TrimSuffix(string(boot), "\n"), ParentPID: uint32(os.Getpid()), ParentStartTicks: start,
		ParentExeSHA256: hex.EncodeToString(h.Sum(nil)), ProgrammeInputsSHA256: seed.ProgrammeInputsSHA256, SeedSHA256: core.Hash(string(raw)), AccountIntentSHA256: core.Hash(string(records[1])),
		JournalDevice: uint64(ds.Dev), JournalInode: ds.Ino, RunLockDevice: uint64(ls.Dev), RunLockInode: ls.Ino, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := loadbalancestream.AccountChildPermitBytes(p); err != nil || !streamAccountParentLockInfo(lock, p) {
		return empty, errLoadBalanceStreamAccount
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	w := &loadBalanceStreamAccountParent{permit: p, j: j, pidfd: pidfd, fdName: strconv.FormatUint(uint64(j.lock.Fd()), 10)}
	defer w.Close()
	if w.current(ctx) != nil || g.current(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	return p, nil
}

func openLoadBalanceStreamAccountPermitRoot(create bool) (*os.Root, os.FileInfo, error) {
	path := loadBalanceStreamAccountPermitsRoot
	if os.Geteuid() != 0 || threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, nil, errLoadBalanceStreamAccount
	}
	if create {
		parent, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			return nil, nil, errLoadBalanceStreamAccount
		}
		defer parent.Close()
		if _, err := parent.Lstat(filepath.Base(path)); errors.Is(err, os.ErrNotExist) {
			if parent.Mkdir(filepath.Base(path), 0700) != nil || ruleFeedStoreSync(parent) != nil {
				return nil, nil, errLoadBalanceStreamAccount
			}
		} else if err != nil {
			return nil, nil, errLoadBalanceStreamAccount
		}
	}
	if threatIDSTrustedParents(path, false) != nil {
		return nil, nil, errLoadBalanceStreamAccount
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, errLoadBalanceStreamAccount
	}
	fail := func() (*os.Root, os.FileInfo, error) { root.Close(); return nil, nil, errLoadBalanceStreamAccount }
	before, e1 := root.Stat(".")
	visible, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(before) || !geoStoreStableInfo(before, visible) {
		return fail()
	}
	dir, err := root.Open(".")
	if err != nil {
		return fail()
	}
	entries, err := dir.ReadDir(129)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 128 || create && len(entries) >= 128 {
		return fail()
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !core.ValidID(strings.TrimSuffix(name, ".json")) {
			return fail()
		}
		info, err := root.Lstat(name)
		if err != nil || !streamJournalFileInfo(info, loadbalancestream.MaxAccountChildPermitBytes) {
			return fail()
		}
	}
	after, err := root.Stat(".")
	if err != nil || !geoStoreStableInfo(before, after) {
		return fail()
	}
	return root, before, nil
}

// Only the original exclusive creator may publish one fresh parent permit.
// Old records, partial bytes and failed writes are retained, never overwritten.
func writeLoadBalanceStreamAccountPermit(ctx context.Context, g *loadBalanceStreamInstallationGate) (loadbalancestream.AccountChildPermit, error) {
	empty := loadbalancestream.AccountChildPermit{}
	p, err := observeLoadBalanceStreamAccountParent(ctx, g)
	if err != nil {
		return empty, err
	}
	raw, err := loadbalancestream.AccountChildPermitBytes(p)
	if err != nil || g.current(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	root, before, err := openLoadBalanceStreamAccountPermitRoot(true)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	// No account effect follows from creation of this private metadata. The
	// independently launched child must freshly recheck every authority.
	f, err := root.OpenFile(p.JobID+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	held, e1 := f.Stat()
	visible, e2 := root.Lstat(p.JobID + ".json")
	after, e3 := root.Stat(".")
	if e1 != nil || e2 != nil || e3 != nil || !streamJournalFileInfo(held, loadbalancestream.MaxAccountChildPermitBytes) ||
		!geoStoreStableInfo(held, visible) || !os.SameFile(before, after) || !memcachedUnixAdminDirectoryInfo(after) || g.current(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	return p, nil
}

type loadBalanceStreamHeldAccountPermit struct {
	root      *os.Root
	file      *os.File
	directory os.FileInfo
	before    os.FileInfo
	value     loadbalancestream.AccountChildPermit
}

func (r *loadBalanceStreamHeldAccountPermit) close() {
	if r != nil {
		if r.file != nil {
			r.file.Close()
			r.file = nil
		}
		if r.root != nil {
			r.root.Close()
			r.root = nil
		}
	}
}
func (r *loadBalanceStreamHeldAccountPermit) current() bool {
	if r == nil || r.root == nil || r.file == nil || threatIDSTrustedParents(loadBalanceStreamAccountPermitsRoot, false) != nil {
		return false
	}
	dir, e1 := r.root.Stat(".")
	namedDir, e2 := os.Lstat(loadBalanceStreamAccountPermitsRoot)
	held, e3 := r.file.Stat()
	visible, e4 := r.root.Lstat(r.value.JobID + ".json")
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && geoStoreStableInfo(r.directory, dir) && geoStoreStableInfo(dir, namedDir) &&
		geoStoreStableInfo(r.before, held) && geoStoreStableInfo(held, visible)
}
func readLoadBalanceStreamAccountPermit(job string) (*loadBalanceStreamHeldAccountPermit, error) {
	if !core.ValidID(job) {
		return nil, errLoadBalanceStreamAccount
	}
	root, directory, err := openLoadBalanceStreamAccountPermitRoot(false)
	if err != nil {
		return nil, err
	}
	r := &loadBalanceStreamHeldAccountPermit{root: root, directory: directory}
	fail := func() (*loadBalanceStreamHeldAccountPermit, error) {
		r.close()
		return nil, errLoadBalanceStreamAccount
	}
	r.file, err = root.OpenFile(job+".json", os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail()
	}
	r.before, err = r.file.Stat()
	if err != nil || !streamJournalFileInfo(r.before, loadbalancestream.MaxAccountChildPermitBytes) {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(r.file, loadbalancestream.MaxAccountChildPermitBytes+1))
	if err != nil || int64(len(raw)) != r.before.Size() {
		return fail()
	}
	r.value, err = loadbalancestream.DecodeAccountChildPermit(raw)
	if err != nil || r.value.JobID != job || !r.current() {
		return fail()
	}
	return r, nil
}
