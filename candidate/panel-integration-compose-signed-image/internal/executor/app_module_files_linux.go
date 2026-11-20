//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// A mount placed at public is the site's own root. Nested mounts, including
// same-filesystem bind mounts, must never become snapshot, watch or write targets.
func moduleSitePublic(site *siteFiles) (*os.File, error) {
	root, err := openRootPathNoLinks(site.root, "public", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	before, beforeErr := site.public.Stat(".")
	now, nowErr := root.Stat()
	if beforeErr != nil || nowErr != nil || !os.SameFile(before, now) {
		root.Close()
		return nil, errors.New("网站根目录在操作期间改变")
	}
	return root, nil
}

func openModuleMountPath(root *os.File, path string, flags int, mode uint32) (*os.File, error) {
	flags |= unix.O_NOFOLLOW | unix.O_CLOEXEC
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NONBLOCK
	}
	fd, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{
		Flags: uint64(flags),
		Mode:  uint64(mode), Resolve: siteOneMountResolve,
	})
	if err != nil {
		if errors.Is(err, unix.EXDEV) {
			err = fmt.Errorf("跨越网站根挂载边界，请排除挂载入口或调整站点目录：%w", err)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd)), nil
}

func moduleMountInfo(root *os.File, path string) (os.FileInfo, error) {
	file, err := openModuleMountPath(root, path, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func openModuleRegular(root *os.File, path string) (*os.File, error) {
	identity, err := openModuleMountPath(root, path, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer identity.Close()
	info, err := identity.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("只允许读取站点内的普通文件")
	}
	return os.OpenFile(identity.Name(), os.O_RDONLY|unix.O_NONBLOCK, 0)
}

// WalkDir can only open directories through the guarded descriptor path.
type moduleMountDirectories struct{ root *os.File }

func (fsys moduleMountDirectories) Open(name string) (fs.File, error) {
	return openModuleMountPath(fsys.root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}

func scanModuleFiles(ctx context.Context, site *siteFiles, excludes []string, snapshot func(string, []byte) error) (map[string]moduleFile, bool, error) {
	files := map[string]moduleFile{}
	var total int64
	partial := false
	entries, metadataBytes := 0, 0
	for _, p := range excludes {
		if !core.ValidFilePath(p, false) {
			return nil, false, errors.New("排除路径无效")
		}
	}
	root, err := moduleSitePublic(site)
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	e := fs.WalkDir(moduleMountDirectories{root}, ".", func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if path == "." {
			return nil
		}
		entries++
		if entries > 100000 {
			partial = true
			return fs.SkipAll
		}
		for _, p := range excludes {
			if path == p || strings.HasPrefix(path, p+"/") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("扫描目录包含符号链接: " + path)
		}
		info, e := moduleMountInfo(root, path)
		if e != nil {
			return e
		}
		if d.IsDir() && info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("扫描目录包含特殊文件")
		}
		if !core.ValidFilePath(path, false) {
			return errors.New("扫描发现不支持的文件路径，请配置排除规则")
		}
		encoded, _ := json.Marshal(path)
		if metadataBytes+len(encoded)+160 > 3<<20 {
			partial = true
			return nil
		}
		if len(files) >= 10000 || info.Size() > 8<<20 || total+info.Size() > moduleMaxBytes {
			partial = true
			return nil
		}
		f, e := openModuleRegular(root, path)
		if e != nil {
			return e
		}
		before, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		b, e := readModuleFileContents(f)
		after, statErr := f.Stat()
		f.Close()
		if e != nil {
			return e
		}
		current, pathErr := moduleMountInfo(root, path)
		if statErr != nil || pathErr != nil || !os.SameFile(info, before) || !os.SameFile(before, current) || !current.Mode().IsRegular() || int64(len(b)) != info.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() || after.Size() != current.Size() || !after.ModTime().Equal(current.ModTime()) || after.Mode() != current.Mode() {
			return errors.New("扫描时文件发生变化")
		}
		total += int64(len(b))
		sha := sha256.Sum256(b)
		hash := hex.EncodeToString(sha[:])
		files[path] = moduleFile{hash, info.Size(), uint32(info.Mode().Perm())}
		metadataBytes += len(encoded) + 160
		if snapshot != nil {
			return snapshot(hash, b)
		}
		return nil
	})
	return files, partial, e
}
func readModuleFile(site *siteFiles, path string) ([]byte, error) {
	root, err := moduleSitePublic(site)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := openModuleRegular(root, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readModuleFileContents(file)
}

func readModuleFileContents(file *os.File) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if len(data) > 8<<20 {
		return nil, errors.New("文件超过 8MiB")
	}
	return data, err
}

func moduleWriteSiteFile(site *siteFiles, path string, data []byte, mode os.FileMode) error {
	return moduleWriteSiteFileGuarded(site, path, data, mode, nil, false)
}

func moduleWriteSiteFileGuarded(site *siteFiles, path string, data []byte, mode os.FileMode, expected *moduleFile, enforce bool) error {
	if !core.ValidFilePath(path, false) {
		return errors.New("文件路径无效")
	}
	root, err := moduleSitePublic(site)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := moduleWriteParent(root, filepath.Dir(path), site.uid, site.gid)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	info, err := moduleMountInfo(parent, name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if info != nil && !info.Mode().IsRegular() {
		return errors.New("拒绝覆盖链接或特殊文件")
	}

	// Keep the temporary inode and final rename anchored to the same parent
	// descriptor. A later mount or symlink must not redirect staging or cleanup.
	temporary := ".cloudstack-" + core.Token()
	out, err := openModuleMountPath(parent, temporary, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(parent.Fd()), temporary, 0)
	err = out.Chown(site.uid, site.gid)
	if err == nil {
		_, err = out.Write(data)
	}
	if err == nil {
		err = out.Chmod(mode & 0777)
	}
	if err == nil {
		err = out.Sync()
	}
	if err = errors.Join(err, out.Close()); err != nil {
		return err
	}
	if enforce && expected != nil {
		current, err := openModuleRegular(root, path)
		if err != nil {
			return err
		}
		before, statErr := current.Stat()
		data, readErr := readModuleFileContents(current)
		current.Close()
		after, pathErr := moduleMountInfo(root, path)
		if statErr != nil || readErr != nil || pathErr != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) ||
			core.Hash(string(data)) != expected.SHA || int64(len(data)) != expected.Size || uint32(after.Mode().Perm()) != expected.Mode {
			return errors.New("写入前目标文件已改变，未覆盖")
		}
	}
	before, err := parent.Stat()
	if err != nil {
		return err
	}
	after, err := moduleMountInfo(root, filepath.Dir(path))
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return errors.New("写入前目标目录已改变，未覆盖")
	}
	if enforce && expected == nil {
		return unix.Renameat2(int(parent.Fd()), temporary, int(parent.Fd()), name, unix.RENAME_NOREPLACE)
	}
	return unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), name)
}

func moduleWriteParent(root *os.File, path string, uid, gid int) (*os.File, error) {
	dir, err := openModuleMountPath(root, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil || path == "." {
		return dir, err
	}
	for _, part := range strings.Split(path, "/") {
		next, err := openModuleMountPath(dir, part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if errors.Is(err, os.ErrNotExist) {
			created := unix.Mkdirat(int(dir.Fd()), part, 0755)
			if created != nil && !errors.Is(created, os.ErrExist) {
				dir.Close()
				return nil, created
			}
			next, err = openModuleMountPath(dir, part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err == nil && created == nil {
				err = next.Chown(uid, gid)
			}
		}
		dir.Close()
		if err != nil {
			if next != nil {
				next.Close()
			}
			return nil, err
		}
		dir = next
	}
	return dir, nil
}
