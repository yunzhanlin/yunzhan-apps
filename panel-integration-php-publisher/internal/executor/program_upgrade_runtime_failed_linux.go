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
)

func runtimeFailedUnitID(name string) (string, bool) {
	const prefix = "panel-install@"
	id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".service")
	return id, core.ValidID(id) && name == prefix+id+".service"
}

const runtimeFailedUnitProperties = "LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainCode,ExecMainStatus,Job,KillMode,ControlGroup,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,Delegate,Type"

// An explicit ordinary exit-code=1, stopped control group and monotonic kernel
// generation are required. Timeout/signal/OOM/restart/unknown state never closes.
// This does not reset failed state or authorize a retry of the retained job.
func runtimeFailedUnitStopped(raw string) (string, bool) {
	want := map[string]string{"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0", "ControlPID": "0", "Result": "exit-code", "ExecMainCode": "1", "ExecMainStatus": "1", "Job": "", "KillMode": "control-group", "ControlGroup": "", "Delegate": "no", "Type": "oneshot"}
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
	return core.Hash(string(bound)), true
}

func runtimeFailedAncestry() bool {
	for name := installState; ; name = filepath.Dir(name) {
		s, err := os.Lstat(name)
		if err != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if name == "/" {
			return true
		}
	}
}

func runtimeFailedRootCurrent(root *os.Root) bool {
	if !runtimeFailedAncestry() {
		return false
	}
	named, err := os.Lstat(installState)
	held, he := root.Stat(".")
	return err == nil && he == nil && runtimeInstallPrivateDirectory(named) && runtimeInstallPrivateDirectory(held) && os.SameFile(named, held)
}

// Unexported fixture seams only. Production always uses fixed trusted roots,
// the original private native status and the fixed readonly Core reader.
// There is no marker, acknowledgement file, CLI bypass or alternate-root flag.
type runtimeFailedUpgradeProof struct {
	open       func() (*os.Root, error)
	current    func(*os.Root) bool
	stopped    func() (string, error)
	validate   func(context.Context, InstallStatus) (string, error)
	checkpoint func() error
}

func (p runtimeFailedUpgradeProof) check(ctx context.Context, id string) error {
	bad := errors.New("原运行时失败安装缺少完整一致的双侧终态和退出代次；阻止程序升级")
	if ctx.Err() != nil || !core.ValidID(id) || p.open == nil || p.current == nil || p.stopped == nil || p.validate == nil {
		return bad
	}
	show, err := p.stopped()
	generation, valid := runtimeFailedUnitStopped(show)
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
	lock, err := root.OpenFile(".native-start.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return bad
	}
	defer lock.Close()
	info, err := lock.Stat()
	named, ne := root.Lstat(".native-start.lock")
	if err != nil || ne != nil || !runtimeInstallSamePrivateFile(info, named) || info.Size() != 0 || unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
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
	if json.Unmarshal(raw, &status) != nil || validateRuntimeInstallStatus(status, id) != nil || status.ExtensionID != "" || status.State != "failed" || status.Error == "" || len(status.Steps) < 1 || status.Steps[len(status.Steps)-1].Message != status.Error {
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
	if p.checkpoint != nil {
		if err := p.checkpoint(); err != nil {
			return err
		}
	}
	last, err := readRuntimeInstallPrivateFile(root, id+".json")
	finalFile, fe := root.Lstat(id + ".json")
	lockAfter, le := lock.Stat()
	lockNamed, lne := root.Lstat(".native-start.lock")
	if err != nil || fe != nil || le != nil || lne != nil || !runtimeInstallSamePrivateFile(originalFile, finalFile) || !bytes.Equal(raw, last) || !runtimeInstallSamePrivateFile(info, lockAfter) || !runtimeInstallSamePrivateFile(lockAfter, lockNamed) || !p.current(root) {
		return bad
	}
	finalBound, err := p.validate(ctx, status)
	if err != nil || finalBound != bound {
		return bad
	}
	show, err = p.stopped()
	finalGeneration, valid := runtimeFailedUnitStopped(show)
	if err != nil || !valid || finalGeneration != generation || ctx.Err() != nil {
		return bad
	}
	return nil
}

func closedRuntimeFailedInstall(ctx context.Context, name string, run Command) bool {
	id, valid := runtimeFailedUnitID(name)
	if !valid || os.Geteuid() != 0 || ctx.Err() != nil || !runtimeFailedAncestry() {
		return false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false
	}
	defer reader.db.Close()
	p := runtimeFailedUpgradeProof{open: runtimeInstallRecordRoot, current: runtimeFailedRootCurrent, stopped: func() (string, error) {
		return run(ctx, "/usr/bin/systemctl", "show", name, "--property="+runtimeFailedUnitProperties, "--no-pager")
	}, validate: func(ctx context.Context, status InstallStatus) (string, error) {
		if !reader.current() {
			return "", errors.New("原生运行时终态 Core 数据库身份变化")
		}
		bound, err := (&core.Store{DB: reader.db}).ValidateRuntimeFailedInstall(ctx, core.RuntimeFailedInstallEvidence{JobID: status.JobID, ReleaseID: status.ReleaseID, Error: status.Error, Steps: status.Steps})
		if !reader.current() {
			return "", errors.New("原生运行时终态 Core 数据库身份变化")
		}
		return bound, err
	}}
	return p.check(ctx, id) == nil
}
