//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"local/panel/internal/core"
)

func apacheBodyOwnedAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Apache 私有记录目录不是绝对规范路径")
	}
	if path != "/" {
		if err := apacheBodyOwnedAncestors(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return ownedRuntimePath(path, true)
}

func readApacheBodyControl(directory, id string) error {
	if directory != apacheBodyRequests && directory != apacheBodyCancellations {
		return errors.New("Apache 控制记录目录未授权")
	}
	if !core.ValidID(id) {
		return errors.New("Apache 控制任务标识无效")
	}
	if err := apacheBodyOwnedAncestors(directory); err != nil {
		return err
	}
	st, err := os.Lstat(directory)
	if err != nil || st.Mode().Perm() != 0700 {
		return errors.New("Apache 控制目录不是私有目录")
	}
	f, err := os.OpenFile(filepath.Join(directory, id+".json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := apacheBodyPrivateFile(f, 1024); err != nil {
		return err
	}
	st, err = f.Stat()
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 || int64(len(b)) != st.Size() {
		return errors.New("Apache 控制记录读取失败、变化或超限")
	}
	var control wafEngineRequest
	if err := apacheBodyDecodeJSON(b, &control); err != nil {
		return err
	}
	if control.Format != 1 || control.JobID != id {
		return errors.New("Apache 控制记录身份异常")
	}
	_, err = time.Parse(time.RFC3339, control.CreatedAt)
	return err
}

func createApacheBodyControl(directory, id string) error {
	if !core.ValidID(id) || (directory != apacheBodyRequests && directory != apacheBodyCancellations) {
		return errors.New("Apache 控制记录标识或目录未授权")
	}
	if err := ensureApacheBodyDirectory(directory, 0700); err != nil {
		return err
	}
	if err := readApacheBodyControl(directory, id); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) >= 64 {
		return errors.New("Apache 控制记录达到 64 份或不可读取；不会自动清除证据")
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 37 || name[32:] != ".json" || !core.ValidID(name[:32]) {
			return errors.New("Apache 控制目录包含未知条目；拒绝不完整清单")
		}
		if err := readApacheBodyControl(directory, name[:32]); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(wafEngineRequest{1, id, core.Now()})
	f, err := os.OpenFile(filepath.Join(directory, id+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
