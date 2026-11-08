//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// ProtectHome deliberately hides root's personal Docker configuration. Pin a
// separate, empty, closed configuration instead of weakening that namespace
// boundary or adopting root's credentials, plugin paths or remote contexts.
func composeCLIEnvironment() ([]string, error) {
	return composeCLIEnvironmentAt("/var/lib/panel-executor")
}

func composeCLIEnvironmentAt(state string) ([]string, error) {
	bad := errors.New("Compose 独立客户端配置的归属、内容或目录不可验证；未执行 Docker 命令")
	tree, err := openDockerMutationTree(state)
	if err != nil {
		return nil, bad
	}
	defer tree.close()
	parent := tree.roots[len(tree.roots)-1]
	const name = "cli-config"
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		// Prepare entirely in a NEW owned directory and commit without replacing
		// even an empty pre-existing directory. Unknown partial state is refused.
		temporary := ".cli-config-init-" + core.ID()
		if parent.Mkdir(temporary, 0700) != nil {
			return nil, bad
		}
		defer parent.RemoveAll(temporary)
		candidate, err := parent.OpenRoot(temporary)
		if err != nil {
			return nil, bad
		}
		f, err := candidate.OpenFile("config.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			candidate.Close()
			return nil, bad
		}
		_, writeErr := f.Write([]byte("{}"))
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || ruleFeedStoreSync(candidate) != nil {
			candidate.Close()
			return nil, bad
		}
		candidate.Close()
		fd, err := parent.Open(".")
		if err != nil {
			return nil, bad
		}
		renameErr := unix.Renameat2(int(fd.Fd()), temporary, int(fd.Fd()), name, unix.RENAME_NOREPLACE)
		fd.Close()
		if renameErr != nil && !errors.Is(renameErr, unix.EEXIST) {
			return nil, bad
		}
		if ruleFeedStoreSync(parent) != nil {
			return nil, bad
		}
	}
	// Re-read in the outer scope: the initialization block has its own error
	// variable. Never mistake the original absence for a failed committed init.
	info, err = parent.Lstat(name)
	if err != nil || !moduleRecordInfo(info, true, false) {
		return nil, bad
	}
	directory, err := parent.OpenRoot(name)
	if err != nil {
		return nil, bad
	}
	defer directory.Close()
	opened, err := directory.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nil, bad
	}
	dir, err := directory.Open(".")
	if err != nil {
		return nil, bad
	}
	entries, readErr := dir.ReadDir(2)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) != 1 || entries[0].Name() != "config.json" {
		return nil, bad
	}
	visible, err := directory.Lstat("config.json")
	if err != nil || !moduleRecordInfo(visible, false, false) || visible.Size() != 2 {
		return nil, bad
	}
	f, err := directory.OpenFile("config.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, bad
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !geoStoreStableInfo(visible, before) {
		return nil, bad
	}
	raw, err := io.ReadAll(io.LimitReader(f, 3))
	if err != nil || !bytes.Equal(raw, []byte("{}")) {
		return nil, bad
	}
	after, e1 := f.Stat()
	named, e2 := directory.Lstat("config.json")
	lastDir, e3 := parent.Lstat(name)
	if e1 != nil || e2 != nil || e3 != nil || !geoStoreStableInfo(before, after) || !geoStoreStableInfo(after, named) || !os.SameFile(info, lastDir) || !moduleRecordInfo(lastDir, true, false) || !tree.current() {
		return nil, bad
	}
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "DOCKER_CONFIG=" + filepath.Join(state, "docker-jobs", name)}, nil
}
