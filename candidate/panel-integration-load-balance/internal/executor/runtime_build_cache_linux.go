//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const runtimeBuildCache = "/var/cache/panel-runtime-build"

// FTP dependencies and native runtime/extension installs share the builder
// account. Serialize their source execution without repairing or truncating
// an existing lock; the lock remains a root-private authority.
func acquireRuntimeNativeBuildSerialization(ctx context.Context) (*os.File, error) {
	const directory = "/var/lib/panel-executor"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("源码构建锁必须由固定 root 服务管理")
	}
	for path := directory; ; path = filepath.Dir(path) {
		if err := ownedRuntimePath(path, true); err != nil {
			return nil, err
		}
		if path == "/" {
			break
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile("build.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !runtimeInstallPrivateFile(info) || info.Size() > 1024 {
		file.Close()
		return nil, errors.New("源码构建锁身份或容量异常，原件保留且未开始安装")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := acquireRuntimeBuildLock(lockCtx, file); err != nil {
		file.Close()
		return nil, fmt.Errorf("等待源码构建锁失败（最多 30 分钟）；未开始安装: %w", err)
	}
	return file, nil
}

func runtimeBuildPrivateFile(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode() == 0600 && identity.Uid == uint32(os.Geteuid()) && identity.Nlink == 1
}

func verifyRuntimeBuildDirectory(path string) error {
	if err := ownedRuntimePath(path, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != os.ModeDir|0755 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != 0 {
		return errors.New("运行时构建目录身份或权限异常，未修复或接管")
	}
	return nil
}

func runtimeBuildCacheRoot() (*os.Root, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("运行时构建缓存仅由固定 root 服务管理")
	}
	for path := runtimeBuildCache; ; path = filepath.Dir(path) {
		if err := ownedRuntimePath(path, true); err != nil {
			return nil, err
		}
		if path == "/" {
			break
		}
	}
	if err := verifyRuntimeBuildDirectory(runtimeBuildCache); err != nil {
		return nil, err
	}
	return os.OpenRoot(runtimeBuildCache)
}

func prepareRuntimeBuildDirectory(id string) (string, error) {
	if !core.ValidID(id) {
		return "", errors.New("无效运行时构建任务标识")
	}
	root, err := runtimeBuildCacheRoot()
	if err != nil {
		return "", err
	}
	defer root.Close()
	base := filepath.Join(runtimeBuildCache, id)
	if _, err := root.Lstat(id); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(runtimeBuildCache)
		if err != nil || len(entries) >= 512 {
			return "", errors.New("运行时构建缓存达到保留限额；未自动删除历史尝试")
		}
		if err := privateBuildDiskBudget(runtimeBuildCache, "运行时"); err != nil {
			return "", err
		}
		if err := root.Mkdir(id, 0755); err != nil {
			return "", err
		}
		if err := root.Chmod(id, 0755); err != nil {
			return "", err
		}
		if err := syncRuntimeDirs(runtimeBuildCache); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if err := verifyRuntimeBuildDirectory(base); err != nil {
		return "", err
	}
	return base, nil
}

func prepareRuntimeBuildWork(base string) (string, error) {
	if filepath.Dir(base) != runtimeBuildCache || !core.ValidID(filepath.Base(base)) {
		return "", errors.New("构建工作路径不属于固定运行时缓存")
	}
	cache, err := runtimeBuildCacheRoot()
	if err != nil {
		return "", err
	}
	defer cache.Close()
	if err := verifyRuntimeBuildDirectory(base); err != nil {
		return "", err
	}
	root, err := cache.OpenRoot(filepath.Base(base))
	if err != nil {
		return "", err
	}
	defer root.Close()
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) >= 32 {
		return "", errors.New("本任务构建尝试达到保留限额；未自动清理旧输出")
	}
	if info, err := root.Lstat("work"); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("旧构建工作目录类型异常，未删除或覆盖")
		}
		owner := info.Sys().(*syscall.Stat_t).Uid
		if owner != 0 {
			builder, err := user.Lookup("panel-build")
			if err != nil || builder.Uid != strconv.FormatUint(uint64(owner), 10) {
				return "", errors.New("旧构建工作目录所有者不可核实，原件保留")
			}
		}
		// Historical compiler output is never executed, used as readiness, or
		// silently removed to make room for the next explicit attempt.
		if err := renameNoReplace(root, "work", "retained-work-"+core.ID()); err != nil {
			return "", err
		}
		if err := syncRuntimeDirs(base); err != nil {
			return "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := root.Mkdir("work", 0755); err != nil {
		return "", err
	}
	if err := root.Chmod("work", 0755); err != nil {
		return "", err
	}
	return filepath.Join(base, "work"), syncRuntimeDirs(base)
}
