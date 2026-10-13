//go:build linux

package executor

import (
	"errors"
	"os"
	"syscall"
)

func fileOwnerForInfo(info os.FileInfo) (*fileOwner, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return nil, errors.New("受管原子写入目标所有者或链接数不可核验")
	}
	return &fileOwner{UID: st.Uid, GID: st.Gid}, nil
}
