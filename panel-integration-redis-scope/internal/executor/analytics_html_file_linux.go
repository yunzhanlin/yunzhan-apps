//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// The optional HTML engine never adopts a writable/shared file, FIFO or a
// file replaced during verification. Its module and public code are immutable.
func analyticsHTMLFileSHA(ctx context.Context, path string, limit int64) (string, error) {
	if err := ownedRuntimePath(path, false); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() > limit {
		return "", errors.New("HTML 引擎文件类型、权限或大小异常")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return "", errors.New("HTML 引擎文件所有者或共享链接异常")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(&contextReader{ctx, f}, limit+1))
	if err != nil || n != before.Size() || n > limit {
		return "", errors.New("HTML 引擎文件摘要读取失败或超过限额")
	}
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(before, current) {
		return "", errors.New("HTML 引擎文件核验期间被替换")
	}
	for _, info := range []os.FileInfo{after, current} {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != owner.Uid || stat.Gid != owner.Gid || stat.Nlink != 1 || info.Mode() != before.Mode() || info.Size() != before.Size() || !info.ModTime().Equal(before.ModTime()) {
			return "", errors.New("HTML 引擎文件字节、权限、所有者或链接在核验期间改变")
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
