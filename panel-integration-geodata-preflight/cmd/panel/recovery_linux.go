//go:build linux

package main

import (
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func recoverLocalAccount(data, name string) error {
	if os.Geteuid() != 0 {
		return errors.New("本机账户恢复只能由 root 执行")
	}
	if filepath.Clean(data) != "/var/lib/panel" {
		return errors.New("开发版救援仅支持受管目录 /var/lib/panel")
	}
	account, e := user.Lookup("panel")
	if e != nil {
		return e
	}
	uid, e := strconv.Atoi(account.Uid)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(account.Gid)
	if e != nil {
		return e
	}
	if uid == 0 {
		return errors.New("面板运行账户不能为 root")
	}
	for _, path := range []string{data, filepath.Join(data, "panel.db")} {
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		info, ok := st.Sys().(*syscall.Stat_t)
		if !ok || info.Uid != uint32(uid) || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0007 != 0 {
			return errors.New("面板数据所有者或权限不符合救援要求")
		}
	}
	// Drop to the existing database owner so WAL/SHM files keep API-readable ownership.
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	if e = syscall.Setuid(uid); e != nil {
		return e
	}
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 75))
	if e != nil {
		return e
	}
	if len(b) > 74 {
		return errors.New("标准输入中的密码超长")
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	s, e := core.OpenStore(filepath.Join(data, "panel.db"))
	if e != nil {
		return e
	}
	defer s.DB.Close()
	return s.RecoverAccount(name, password)
}
