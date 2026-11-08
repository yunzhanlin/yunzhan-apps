//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// An alert reader does not own the executor mutation mutex. Hold the private
// ancestry and original installed-record identity instead. A concurrent
// uninstall, replacement or metadata upgrade invalidates the whole response.
type moduleAlertReadGuard struct {
	dir       *modulePrivateDirectory
	installed os.FileInfo
}

func (s *Service) beginModuleAlertRead(id string) (*moduleAlertReadGuard, bool, error) {
	dir, err := s.moduleRecordDirectory(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	info, err := dir.Lstat("installed.json")
	if errors.Is(err, os.ErrNotExist) && dir.current() {
		dir.Close()
		return nil, false, nil
	}
	if err != nil {
		dir.Close()
		return nil, false, errors.New("告警源安装记录无法核对")
	}
	guard := &moduleAlertReadGuard{dir: dir, installed: info}
	if _, err = s.moduleInstalledRecord(id); err != nil {
		dir.Close()
		return nil, false, err
	}
	if err = guard.check(context.Background()); err != nil {
		dir.Close()
		return nil, false, err
	}
	return guard, true, nil
}

func (g *moduleAlertReadGuard) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := g.dir.Lstat("installed.json")
	if err != nil || !g.dir.current() || !os.SameFile(g.installed, after) || !moduleRecordInfo(after, false, false) || g.installed.Size() != after.Size() || !g.installed.ModTime().Equal(after.ModTime()) || g.installed.Mode() != after.Mode() {
		return errors.New("告警源安装身份在读取期间改变，未返回旧状态")
	}
	a, aok := g.installed.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	if !aok || !bok || a.Uid != b.Uid || a.Gid != b.Gid || a.Nlink != b.Nlink || a.Ctim != b.Ctim {
		return errors.New("告警源安装记录身份或权限在读取期间改变")
	}
	return nil
}
