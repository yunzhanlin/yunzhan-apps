//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Hold every named ancestor, not only a detached project fd. Existing paths
// are never created, repaired, chmodded or followed through links by a preview.
type composeUpdateDirectory struct {
	root        *os.Root
	roots       []*os.Root
	paths       []string
	privateFrom int
}

func (d *composeUpdateDirectory) Close() {
	for i := len(d.roots) - 1; i >= 0; i-- {
		_ = d.roots[i].Close()
	}
}
func (d *composeUpdateDirectory) current() bool {
	for i, r := range d.roots {
		opened, e := r.Stat(".")
		named, ne := os.Lstat(d.paths[i])
		if e != nil || ne != nil || !os.SameFile(opened, named) || !moduleRecordInfo(opened, true, i < d.privateFrom) || !moduleRecordInfo(named, true, i < d.privateFrom) {
			return false
		}
	}
	return true
}

// The production caller supplies only the fixed dockerProjects constant.
// A separate explicit base exists for real trusted-root filesystem fixtures,
// never an HTTP path, environment override or privileged caller assertion.
func openComposeUpdateDirectory(base, id string) (*composeUpdateDirectory, error) {
	if os.Geteuid() != 0 || !core.ValidID(id) || !filepath.IsAbs(base) || filepath.Clean(base) != base || base == "/" {
		return nil, errors.New("Compose 原项目受信位置或执行器身份无效")
	}
	names := strings.Split(strings.TrimPrefix(filepath.Join(base, id), "/"), "/")
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	d := &composeUpdateDirectory{root: root, roots: []*os.Root{root}, paths: []string{"/"}, privateFrom: len(names) - 1}
	fail := func() (*composeUpdateDirectory, error) {
		d.Close()
		return nil, errors.New("Compose 原项目目录身份、权限或命名祖先变化")
	}
	for i, name := range names {
		before, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && d.current() {
			// Preserve a real absence only below already verified held/named
			// ancestors. Callers must not confuse missing jobs with unsafe paths.
			d.Close()
			return nil, err
		}
		if err != nil || !moduleRecordInfo(before, true, i+1 < d.privateFrom) {
			return fail()
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return fail()
		}
		d.roots = append(d.roots, child)
		d.paths = append(d.paths, filepath.Join(d.paths[len(d.paths)-1], name))
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(before, opened) || !moduleRecordInfo(opened, true, i+1 < d.privateFrom) {
			return fail()
		}
		root = child
		d.root = child
	}
	if !d.current() {
		return fail()
	}
	return d, nil
}

func sameComposeUpdateFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || !moduleRecordInfo(a, false, false) || !moduleRecordInfo(b, false, false) || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return ok && yok && x.Gid == y.Gid && x.Ctim == y.Ctim
}

func (d *composeUpdateDirectory) read(name string, limit int64) ([]byte, os.FileInfo, error) {
	if (name != "metadata.json" && name != "compose.yaml") || limit < 1 || limit > 48*1024 || !d.current() {
		return nil, nil, errors.New("Compose 原项目读取范围或目录身份无效")
	}
	before, err := d.root.Lstat(name)
	if err != nil || !moduleRecordInfo(before, false, false) || before.Size() < 1 || before.Size() > limit {
		return nil, nil, errors.New("Compose 原项目文件身份、权限或容量异常")
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errors.New("Compose 原项目文件打开失败")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameComposeUpdateFile(before, opened) {
		return nil, nil, errors.New("Compose 原项目文件打开期间变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, se := f.Stat()
	visible, ve := d.root.Lstat(name)
	if err != nil || se != nil || ve != nil || int64(len(raw)) != before.Size() || !sameComposeUpdateFile(before, after) || !sameComposeUpdateFile(before, visible) || !d.current() {
		return nil, nil, errors.New("Compose 原项目读取期间身份或内容变化")
	}
	return raw, before, nil
}
