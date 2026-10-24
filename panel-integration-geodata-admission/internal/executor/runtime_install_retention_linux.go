//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
)

const runtimeInstallRecordLimit = 256 * 1024

// The native ledger is Root-private authority, not a compiler-owned input.
// Refuse links, oversized/non-regular records and foreign ownership without
// repairing them. OpenRoot confines every leaf to the verified fixed directory.
func runtimeInstallRecordRoot() (*os.Root, error) {
	info, err := os.Lstat(installState)
	if err != nil {
		return nil, err
	}
	if !runtimeInstallPrivateDirectory(info) {
		return nil, errors.New("原生安装记录目录身份或权限异常，未修复")
	}
	root, err := os.OpenRoot(installState)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !runtimeInstallPrivateDirectory(opened) {
		root.Close()
		return nil, errors.New("原生安装记录目录在打开期间变化")
	}
	return root, nil
}

func runtimeInstallPrivateDirectory(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	// The HTTP executor runs as root:panel whereas native workers run as
	// root:root. Group has no access in 0700/0600; either producer is valid.
	return ok && info.IsDir() && info.Mode() == os.ModeDir|0700 && identity.Uid == 0
}

func runtimeInstallPrivateFile(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode() == 0600 && identity.Uid == 0 && identity.Nlink == 1
}

func runtimeInstallSamePrivateFile(a, b os.FileInfo) bool {
	if !runtimeInstallPrivateFile(a) || !runtimeInstallPrivateFile(b) {
		return false
	}
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	// Access time may legitimately change on read; byte/identity authority may not.
	return x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func readRuntimeInstallPrivateFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !runtimeInstallPrivateFile(before) || before.Size() < 1 || before.Size() > runtimeInstallRecordLimit {
		return nil, errors.New("原生安装记录类型、大小、权限或所有者异常，原件保留")
	}
	data, err := io.ReadAll(io.LimitReader(f, runtimeInstallRecordLimit+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	current, currentErr := root.Lstat(name)
	if err != nil || currentErr != nil || !runtimeInstallSamePrivateFile(before, after) || !runtimeInstallSamePrivateFile(after, current) || int64(len(data)) != before.Size() {
		return nil, errors.New("原生安装记录在读取期间变化，未推断结果")
	}
	return data, nil
}

func readRuntimeInstallRecordBytes(id string) ([]byte, error) {
	if !core.ValidID(id) {
		return nil, errors.New("无效任务标识")
	}
	root, err := runtimeInstallRecordRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRuntimeInstallPrivateFile(root, id+".json")
}

func runtimeInstallStartLock(ctx context.Context) (*os.File, error) {
	root, err := runtimeInstallRecordRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(".native-start.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !runtimeInstallPrivateFile(info) || info.Size() != 0 {
		f.Close()
		return nil, errors.New("安装启动锁身份不可核实，未启动或修复")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := acquireRuntimeBuildLock(lockCtx, f); err != nil {
		f.Close()
		return nil, errors.New("安装启动请求正在处理，请稍后核对原任务")
	}
	return f, nil
}

func retainRuntimeInstallAttempt(id string, old InstallStatus) error {
	if err := validateRuntimeInstallStatus(old, id); err != nil || old.State == "succeeded" {
		return errors.New("原安装尝试不可核实或已成功，未覆盖")
	}
	root, err := runtimeInstallRecordRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := readRuntimeInstallPrivateFile(root, id+".json")
	if err != nil {
		return err
	}
	var current InstallStatus
	if json.Unmarshal(data, &current) != nil || !reflect.DeepEqual(old, current) {
		return errors.New("原安装尝试在重试前发生变化，未覆盖")
	}
	if err = root.Mkdir("retained", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat("retained")
	if err != nil || !runtimeInstallPrivateDirectory(info) {
		return errors.New("保留记录目录身份异常，未覆盖或修复")
	}
	retained, err := root.OpenRoot("retained")
	if err != nil {
		return err
	}
	defer retained.Close()
	opened, err := retained.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !runtimeInstallPrivateDirectory(opened) {
		return errors.New("保留记录目录在打开期间变化")
	}
	sum := sha256.Sum256(data)
	name := id + "-" + hex.EncodeToString(sum[:]) + ".json"
	f, err := retained.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		previous, readErr := readRuntimeInstallPrivateFile(retained, name)
		if readErr != nil || !bytes.Equal(previous, data) {
			return errors.New("已有保留记录不匹配，未覆盖或重复启动")
		}
	} else if err != nil {
		return err
	} else {
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		verified, err := readRuntimeInstallPrivateFile(retained, name)
		if err != nil || !bytes.Equal(verified, data) {
			return errors.New("保留安装记录完整性核对失败，未覆盖原件")
		}
	}
	return syncRuntimeDirs(filepath.Join(installState, "retained"), installState)
}
