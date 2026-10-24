//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

// This independent protocol does NOT widen runtimeFailedUnitStopped: an OOM
// is never an ordinary recorded exit. It recognizes only the observed oneshot
// OOM/TERM generation, after systemd has removed every process/control group.
// A missing, active, queued, delegated, signalled-only or unknown unit refuses.
func runtimeCompileOOMUnitStopped(raw string) (string, bool) {
	want := map[string]string{"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0", "ControlPID": "0", "Result": "oom-kill", "ExecMainCode": "2", "ExecMainStatus": "15", "Job": "", "KillMode": "control-group", "ControlGroup": "", "Delegate": "no", "Type": "oneshot"}
	if len(raw) > 4096 || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(raw, "\x00\r") {
		return "", false
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", false
		}
		if _, duplicate := values[key]; duplicate {
			return "", false
		}
		if expected, known := want[key]; known {
			if value != expected {
				return "", false
			}
		} else if key != "ExecMainPID" && key != "ExecMainStartTimestampMonotonic" && key != "ExecMainExitTimestampMonotonic" {
			return "", false
		}
		values[key] = value
	}
	if len(values) != len(want)+3 {
		return "", false
	}
	var generation []uint64
	for _, key := range []string{"ExecMainPID", "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic"} {
		n, err := strconv.ParseUint(values[key], 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != values[key] {
			return "", false
		}
		generation = append(generation, n)
	}
	if generation[0] < 2 || generation[0] > 1<<31-1 || generation[2] < generation[1] {
		return "", false
	}
	bound, _ := json.Marshal(values)
	return core.Hash("php-compile-oom-stopped-v1\x00" + string(bound)), true
}

func runtimeCompileOOMReadLease(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	bad := errors.New("编译 OOM 构建/调度锁身份或只读租约不可核实")
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, bad
	}
	info, err := f.Stat()
	named, ne := root.Lstat(name)
	if err != nil || ne != nil || !runtimeInstallSamePrivateFile(info, named) || info.Size() != 0 || unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		f.Close()
		return nil, nil, bad
	}
	return f, info, nil
}

func runtimeCompileOOMLeaseCurrent(root *os.Root, name string, f *os.File, original os.FileInfo) bool {
	info, err := f.Stat()
	named, ne := root.Lstat(name)
	return err == nil && ne == nil && runtimeInstallSamePrivateFile(original, info) && runtimeInstallSamePrivateFile(info, named)
}

// A shared read-only lease on the EXISTING global builder lock proves that no
// other use of panel-build is running while this proof is collected. Never
// create, truncate, repair or normalize the original lock or its directories.
func runtimeCompileOOMBuildFence() (func() bool, func(), error) {
	const path = "/var/lib/panel-executor"
	if os.Geteuid() != 0 || !runtimeFailedAncestry() {
		return nil, nil, errors.New("编译 OOM 构建锁祖先不可核实")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	f, info, err := runtimeCompileOOMReadLease(root, "build.lock")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	current := func() bool {
		a, err := os.Lstat(path)
		b, be := root.Stat(".")
		return err == nil && be == nil && runtimeFailedAncestry() && os.SameFile(a, b) && runtimeCompileOOMLeaseCurrent(root, "build.lock", f, info)
	}
	return current, func() { f.Close(); root.Close() }, nil
}

// Only fixed PHP publication names are considered. All trusted ancestor
// identities, not just a projected directory existence boolean, enter the
// repeated-read binding. Any existing final/pending path (even a link/FIFO),
// unsafe parent or concurrent replacement refuses; nothing is removed.
func runtimeCompileOOMPublication(ctx context.Context, parent, version, id string) (string, error) {
	bad := errors.New("编译 OOM 存在运行时发布路径或路径身份不可核实")
	if ctx.Err() != nil || !core.ValidID(id) || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent || filepath.Base(version) != version || version == "." || version == ".." {
		return "", bad
	}
	var snapshots []programQueueSnapshot
	var identities []any
	for path := parent; ; path = filepath.Dir(path) {
		if ctx.Err() != nil || ownedRuntimePath(path, true) != nil {
			return "", bad
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", bad
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return "", bad
		}
		snapshots = append(snapshots, programQueueSnapshot{path: path, info: info})
		identities = append(identities, []any{path, st.Dev, st.Ino, st.Mode, st.Uid, st.Gid, st.Nlink, st.Size, st.Mtim, st.Ctim})
		if path == "/" {
			break
		}
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return "", bad
	}
	defer root.Close()
	held, err := root.Stat(".")
	if err != nil || !programQueueSame(snapshots[0].info, held) {
		return "", bad
	}
	for _, name := range []string{version, version + ".pending-" + id} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return "", bad
		}
	}
	for _, snapshot := range snapshots {
		info, err := os.Lstat(snapshot.path)
		if err != nil || !programQueueSame(snapshot.info, info) || ctx.Err() != nil {
			return "", bad
		}
	}
	bound, _ := json.Marshal([]any{version, id, identities})
	return core.Hash(string(bound)), nil
}

// Unexported fixture seams. Production has fixed Root/Core/lock/publication
// paths; no marker, alternative CLI root, recovery, dispatch or retry flag.
type runtimeCompileOOMUpgradeProof struct {
	open        func() (*os.Root, error)
	current     func(*os.Root) bool
	stopped     func() (string, error)
	validate    func(context.Context, InstallStatus) (string, error)
	unpublished func(context.Context, InstallStatus) (string, error)
	fence       func() (func() bool, func(), error)
	checkpoint  func() error
}

func (p runtimeCompileOOMUpgradeProof) check(ctx context.Context, id string) error {
	bad := errors.New("编译 OOM 缺少原始失败、停止代次、双锁与未发布证据；阻止程序升级")
	if ctx.Err() != nil || !core.ValidID(id) || p.open == nil || p.current == nil || p.stopped == nil || p.validate == nil || p.unpublished == nil || p.fence == nil {
		return bad
	}
	show, err := p.stopped()
	generation, valid := runtimeCompileOOMUnitStopped(show)
	if err != nil || !valid {
		return bad
	}
	root, err := p.open()
	if err != nil {
		return err
	}
	defer root.Close()
	if !p.current(root) {
		return bad
	}
	lock, lockInfo, err := runtimeCompileOOMReadLease(root, ".native-start.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	fenceCurrent, closeFence, err := p.fence()
	if err != nil || fenceCurrent == nil || closeFence == nil {
		return bad
	}
	defer closeFence()
	if !fenceCurrent() {
		return bad
	}
	originalFile, err := root.Lstat(id + ".json")
	if err != nil || !runtimeInstallPrivateFile(originalFile) {
		return bad
	}
	raw, err := readRuntimeInstallPrivateFile(root, id+".json")
	if err != nil {
		return err
	}
	var status InstallStatus
	if json.Unmarshal(raw, &status) != nil || validateRuntimeInstallStatus(status, id) != nil || status.ExtensionID != "" || status.State != "running" || status.Error != "" || !core.RuntimeCompileOOMSteps(status.ReleaseID, status.Steps) {
		return bad
	}
	canonical, _ := json.Marshal(status)
	if !bytes.Equal(raw, canonical) {
		return bad
	}
	bound, err := p.validate(ctx, status)
	if err != nil || !programQueueDiagnosticSHA.MatchString(bound) {
		return bad
	}
	publication, err := p.unpublished(ctx, status)
	if err != nil || !programQueueDiagnosticSHA.MatchString(publication) {
		return bad
	}
	if p.checkpoint != nil {
		if err := p.checkpoint(); err != nil {
			return err
		}
	}
	last, err := readRuntimeInstallPrivateFile(root, id+".json")
	finalFile, fe := root.Lstat(id + ".json")
	if err != nil || fe != nil || !runtimeInstallSamePrivateFile(originalFile, finalFile) || !bytes.Equal(raw, last) || !runtimeCompileOOMLeaseCurrent(root, ".native-start.lock", lock, lockInfo) || !p.current(root) || !fenceCurrent() {
		return bad
	}
	finalBound, err := p.validate(ctx, status)
	if err != nil || finalBound != bound {
		return bad
	}
	finalPublication, err := p.unpublished(ctx, status)
	if err != nil || finalPublication != publication {
		return bad
	}
	show, err = p.stopped()
	finalGeneration, valid := runtimeCompileOOMUnitStopped(show)
	if err != nil || !valid || finalGeneration != generation || ctx.Err() != nil || !fenceCurrent() || !runtimeCompileOOMLeaseCurrent(root, ".native-start.lock", lock, lockInfo) || !p.current(root) {
		return bad
	}
	return nil
}

func closedRuntimeCompileOOMInstall(ctx context.Context, name string, run Command) bool {
	id, valid := runtimeFailedUnitID(name)
	if !valid || os.Geteuid() != 0 || ctx.Err() != nil || !runtimeFailedAncestry() {
		return false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false
	}
	defer reader.db.Close()
	p := runtimeCompileOOMUpgradeProof{open: runtimeInstallRecordRoot, current: runtimeFailedRootCurrent, fence: runtimeCompileOOMBuildFence,
		stopped: func() (string, error) {
			return run(ctx, "/usr/bin/systemctl", "show", name, "--property="+runtimeFailedUnitProperties, "--no-pager")
		},
		validate: func(ctx context.Context, status InstallStatus) (string, error) {
			if !reader.current() {
				return "", errors.New("编译 OOM 原始 Core 数据库身份变化")
			}
			bound, err := (&core.Store{DB: reader.db}).ValidateRuntimeCompileOOMInstall(ctx, core.RuntimeCompileOOMInstallEvidence{JobID: status.JobID, ReleaseID: status.ReleaseID, Steps: status.Steps})
			if !reader.current() {
				return "", errors.New("编译 OOM 原始 Core 数据库身份变化")
			}
			return bound, err
		},
		unpublished: func(ctx context.Context, status InstallStatus) (string, error) {
			r, ok := runtimecatalog.Find(status.ReleaseID)
			if !ok || r.Family != "php" {
				return "", errors.New("编译 OOM 发布目录版本未知")
			}
			return runtimeCompileOOMPublication(ctx, filepath.Dir(r.Prefix()), r.Version, status.JobID)
		},
	}
	return p.check(ctx, id) == nil
}
