//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// The caller has stopped the attested capture process and holds the IDS
// configuration lock. A visible event is not durable merely because the
// daemon exited: its writes may still be in the kernel page cache.
// Sync only the verified event descriptor and its directory, without creating,
// replacing, truncating, reowning, or parsing any retained user data.
func (s *Service) syncStoppedThreatIDSOutput(ctx context.Context, account threatIDSAccount) (bool, int64, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	file, size, err := s.openThreatIDSLiveFile(account)
	if err != nil {
		return false, 0, err
	}
	if file != nil {
		defer file.Close()
	}
	logdir := s.systemPath("/var/lib/panel-network-ids/logs")
	root, err := os.OpenRoot(logdir)
	if err != nil {
		return false, 0, err
	}
	defer root.Close()
	dir, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return false, 0, err
	}
	defer dir.Close()
	beforeDir, err := dir.Stat()
	if err != nil {
		return false, 0, err
	}
	var before os.FileInfo
	if file != nil {
		before, err = file.Stat()
		if err != nil {
			return false, 0, err
		}
		if err := file.Sync(); err != nil {
			return false, 0, err
		}
	}
	// Persist the engine-created directory entry as well as its contents.
	if err := dir.Sync(); err != nil {
		return false, 0, err
	}
	currentDir, err := os.Lstat(filepath.Clean(logdir))
	if err != nil || !os.SameFile(beforeDir, currentDir) || currentDir.Mode()&os.ModeSymlink != 0 {
		return false, 0, errors.New("IDS 日志同步期间目录身份发生变化；未宣称落盘完成")
	}
	current, pathErr := root.Lstat("eve.json")
	if file == nil {
		if !os.IsNotExist(pathErr) {
			return false, 0, errors.New("IDS 停止后出现未知日志文件；未宣称落盘完成")
		}
		return false, 0, ctx.Err()
	}
	after, err := file.Stat()
	identity := func(info os.FileInfo) bool {
		if info == nil {
			return false
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 &&
			owner.Uid == account.UID && owner.Gid == account.GID && owner.Nlink == 1 &&
			os.SameFile(before, info) && info.Size() == size && before.ModTime().Equal(info.ModTime())
	}
	if err != nil || pathErr != nil || !identity(after) || !identity(current) {
		return false, 0, errors.New("IDS 停止日志在同步期间被替换或改变；未宣称落盘完成")
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	return true, size, nil
}
