//go:build linux

package executor

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// os.Root confines paths but can resolve contained links, including when its
// OpenFile receives O_NOFOLLOW. Walk the directory descriptors ourselves when
// an operation promises to reject links in every path component.
func openRootPathNoLinks(root *os.Root, path string, flags int, mode os.FileMode) (*os.File, error) {
	if root == nil || path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("文件路径包含无效分量")
	}
	parts := strings.Split(path, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." || part == "" || part == "." && path != "." {
			return nil, errors.New("文件路径包含无效分量")
		}
	}
	anchor, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	parent, owned := int(anchor.Fd()), -1
	defer func() {
		if owned >= 0 {
			unix.Close(owned)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		if owned >= 0 {
			unix.Close(owned)
		}
		parent, owned = next, next
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// NewFile cannot set os.Root's private inRoot bit. ReadDir's DirEntry.Info
	// otherwise resolves the display name against cwd. A proc descriptor name
	// keeps that lookup on this opened directory even after its path is replaced.
	return os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd)), nil
}

// Creating through os.Root.Mkdir could follow a contained parent link before
// a later open detects it. Validate and pin the parent before mkdirat instead.
func mkdirRootPathNoLinks(root *os.Root, path string, mode os.FileMode) error {
	if path == "" || path == "." || filepath.Base(path) == ".." || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "\x00") {
		return errors.New("目录路径包含无效分量")
	}
	parent, err := openRootPathNoLinks(root, filepath.Dir(path), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	return unix.Mkdirat(int(parent.Fd()), filepath.Base(path), uint32(mode.Perm()))
}
