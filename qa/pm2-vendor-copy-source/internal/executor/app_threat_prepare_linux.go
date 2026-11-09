//go:build linux

package executor

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func threatIDSTrustedParents(path string, create bool) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("IDS 原生目录必须为明确 root 路径")
	}
	current := "/"
	for _, part := range append([]string{""}, strings.Split(strings.TrimPrefix(path, "/"), "/")...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		if _, err := os.Lstat(current); errors.Is(err, os.ErrNotExist) && create {
			if err = os.Mkdir(current, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			// Only a directory actually created here receives exact permissions.
			if err == nil {
				if err = os.Chmod(current, 0755); err != nil {
					return err
				}
				parent, e := os.Open(filepath.Dir(current))
				if e != nil {
					return e
				}
				e = parent.Sync()
				parent.Close()
				if e != nil {
					return e
				}
			}
		}
		if ownedRuntimePath(current, true) != nil {
			return errors.New("IDS 目录父级为链接、非 root 或可写；未修复")
		}
	}
	return nil
}

var threatIDSStageName = regexp.MustCompile(`^\.prepare-[0-9]+$`)

func threatIDSPrepareBudget(base string) error {
	if err := threatIDSTrustedParents(base, false); err != nil {
		return err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	stages := 0
	count := 0
	total := int64(0)
	for _, entry := range entries {
		if threatIDSStageName.MatchString(entry.Name()) {
			stages++
		} else if !threatIDSPrefix.MatchString(entry.Name()) && entry.Name() != "rules" {
			return errors.New("IDS 原生目录存在未知条目；保留并拒绝新准备")
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("IDS 原生准备目录身份异常")
		}
		err = filepath.WalkDir(filepath.Join(base, entry.Name()), func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			count++
			info, e := d.Info()
			if e != nil {
				return e
			}
			if info.Mode().IsRegular() {
				total += info.Size()
			} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("IDS 准备证据包含非常规条目")
			}
			if count > 10000 || total > 512<<20 {
				return errors.New("IDS 保留准备证据达到 512 MiB/10000 条上限；未清理")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if stages >= 8 {
		return errors.New("IDS 保留准备阶段达到 8 份上限；需单独核对归档，不自动删除")
	}
	var storage unix.Statfs_t
	if err = unix.Statfs(base, &storage); err != nil {
		return err
	}
	if storage.Bsize <= 0 || storage.Bavail < uint64((1<<30)/storage.Bsize) {
		return errors.New("IDS 准备需要至少 1 GiB 可用空间；未扩大交换或删除文件")
	}
	return nil
}

func threatIDSPrepareLock(dir string) (*os.File, error) {
	if err := threatIDSTrustedParents(dir, true); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "native-prepare.lock")
	if _, err := os.Lstat(name); err == nil {
		if ownedRuntimePath(name, false) != nil {
			return nil, errors.New("IDS 准备锁身份异常")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		file.Close()
		return nil, errors.New("IDS 准备锁模式或文件身份异常")
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("已有 IDS 原生准备运行；不并行写入")
	}
	return file, nil
}

func threatIDSDebFiles(ctx context.Context, pkg string) (map[string][]byte, error) {
	return threatIDSDebSelected(ctx, pkg, readThreatIDSPackageFiles)
}

func threatIDSDebSelected(ctx context.Context, pkg string, read func(context.Context, io.Reader) (map[string][]byte, error)) (map[string][]byte, error) {
	child, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(child, "/usr/bin/dpkg-deb", "--fsys-tarfile", pkg)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	output := &boundedBuffer{max: 16 << 10}
	cmd.Stderr = output
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	files, err := read(child, pipe)
	if err != nil {
		cancel()
		_ = cmd.Wait()
		return nil, err
	}
	if err = cmd.Wait(); err != nil {
		return nil, errors.New("IDS 原生包流展开失败；未执行维护脚本或写出包目录")
	}
	return files, nil
}
