//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func threatIDSRetiringProducerName(id string) string {
	return "retiring-" + threatIDSProducerName(id)
}

// The producer's bytes are not archive authority and may have changed through
// an old descriptor. Retirement still requires its exact original private
// pathname identity; it never follows links or deletes an unknown object.
func threatIDSProducerIdentity(directory *os.File, name string, witness threatIDSArchiveSource) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "owned-retiring-ids-producer")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	var named unix.Stat_t
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		owner.Nlink != 1 || owner.Uid != 0 || owner.Gid != 0 || uint64(owner.Dev) != witness.Device || owner.Ino != witness.Inode ||
		unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Mode&unix.S_IFMT != unix.S_IFREG ||
		named.Dev != uint64(owner.Dev) || named.Ino != owner.Ino {
		return errors.New("IDS 原来源退役对象身份、账户或权限改变；原文件保留")
	}
	return nil
}

func threatIDSStageProducerRetirement(ctx context.Context, dir string, entry threatIDSArchive) error {
	if entry.Source == nil {
		return nil
	}
	if !validThreatIDSArchive(entry) || ctx.Err() != nil {
		return errors.New("IDS 原来源退役记录无效或操作已取消")
	}
	directory, err := threatIDSOpenCopyDirectory(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	name, stage := threatIDSProducerName(entry.ID), threatIDSRetiringProducerName(entry.ID)
	var original, staged unix.Stat_t
	originalErr := unix.Fstatat(int(directory.Fd()), name, &original, unix.AT_SYMLINK_NOFOLLOW)
	stageErr := unix.Fstatat(int(directory.Fd()), stage, &staged, unix.AT_SYMLINK_NOFOLLOW)
	if originalErr != nil && !errors.Is(originalErr, syscall.ENOENT) || stageErr != nil && !errors.Is(stageErr, syscall.ENOENT) {
		return errors.New("IDS 原来源退役路径不可核对")
	}
	if originalErr == nil {
		if stageErr == nil {
			return errors.New("IDS 原来源退役槽冲突；未覆盖")
		}
		if err := threatIDSProducerIdentity(directory, name, *entry.Source); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := unix.Renameat2(int(directory.Fd()), name, int(directory.Fd()), stage, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := directory.Sync(); err != nil {
			return err
		}
	} else if stageErr != nil {
		return errors.New("IDS 原来源缺失且尚未授权移除；保留独立副本")
	}
	if err := threatIDSProducerIdentity(directory, stage, *entry.Source); err != nil {
		return err
	}
	return threatIDSCopyDirectoryCurrent(directory, dir)
}

func threatIDSUnlinkRetiringProducer(ctx context.Context, dir string, entry threatIDSArchive, authorized bool) error {
	if entry.Source == nil {
		return nil
	}
	if !authorized || !validThreatIDSArchive(entry) || ctx.Err() != nil {
		return errors.New("IDS 原来源移除尚未授权或操作已取消")
	}
	directory, err := threatIDSOpenCopyDirectory(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	var original unix.Stat_t
	originalErr := unix.Fstatat(int(directory.Fd()), threatIDSProducerName(entry.ID), &original, unix.AT_SYMLINK_NOFOLLOW)
	if originalErr == nil {
		return errors.New("IDS 已授权退役后原来源路径重新出现；未删除")
	}
	if !errors.Is(originalErr, syscall.ENOENT) {
		return originalErr
	}
	name := threatIDSRetiringProducerName(entry.ID)
	if err := threatIDSProducerIdentity(directory, name, *entry.Source); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return threatIDSCopyDirectoryCurrent(directory, dir)
		}
		return err
	}
	if err := threatIDSCopyDirectoryCurrent(directory, dir); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return threatIDSCopyDirectoryCurrent(directory, filepath.Clean(dir))
}
