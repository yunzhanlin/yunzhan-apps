//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const remoteCopyMaxRecords = 128
const remoteCopyMaxAttempts = 8
const remoteCopyMaxBytes int64 = 1 << 30
const remoteCopyRecordLimit int64 = 32 << 10
const remoteCopyFileLimit int64 = 8 << 20

type remoteCopyIntent struct {
	Format    int                       `json:"format"`
	Version   string                    `json:"app_version"`
	Source    remoteBackupArchiveRecord `json:"source"`
	CreatedAt string                    `json:"created_at"`
}
type remoteCopyAttempt struct {
	Format    int    `json:"format"`
	ID        string `json:"id"`
	IntentSHA string `json:"intent_sha256"`
	CreatedAt string `json:"created_at"`
}
type remoteCopyFile struct {
	Name   string `json:"name"`
	SHA    string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type remoteCopyResult struct {
	Format      int              `json:"format"`
	IntentSHA   string           `json:"intent_sha256"`
	AttemptID   string           `json:"attempt_id"`
	Files       []remoteCopyFile `json:"files"`
	CompletedAt string           `json:"completed_at"`
}
type remoteCopyRetained struct {
	Format     int              `json:"format"`
	IntentSHA  string           `json:"intent_sha256"`
	Files      []remoteCopyFile `json:"files"`
	RetainedAt string           `json:"retained_at"`
}
type remoteCopyRecord struct {
	Intent   remoteCopyIntent
	SHA      string
	Result   *remoteCopyResult
	Retained *remoteCopyRetained
	Attempts []string
	Bytes    int64
}

// Keep the existing configured module anchor and every opened parent held.
// Existing namespaces are validated, never chmod/chowned or replaced.
func (s *Service) remoteCopyDirectory(target, transaction, attempt string, create bool) (*modulePrivateDirectory, error) {
	if target != "" && !syncPlanID.MatchString(target) || transaction != "" && (target == "" || !core.ValidID(transaction)) || attempt != "" && (transaction == "" || !core.ValidID(attempt)) {
		return nil, errors.New("独立备份标识无效")
	}
	d, err := s.moduleRecordDirectory("files-sync")
	if err != nil {
		return nil, err
	}
	names := []string{"remote", "independent-backups"}
	if target != "" {
		names = append(names, target)
	}
	if transaction != "" {
		names = append(names, transaction)
	}
	if attempt != "" {
		names = append(names, "attempts", attempt)
	}
	for _, name := range names {
		if err = remoteCopyDescend(d, name, create); err != nil {
			d.Close()
			return nil, err
		}
	}
	return d, nil
}
func remoteCopyDescend(d *modulePrivateDirectory, name string, create bool) error {
	if !d.current() || filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("独立备份父目录身份变化")
	}
	info, err := d.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = d.Mkdir(name, 0700); err != nil {
			return err
		}
		if err = remoteCopySync(d); err != nil {
			return err
		}
		info, err = d.Lstat(name)
	}
	if err != nil {
		return err
	}
	if !moduleRecordInfo(info, true, false) {
		return errors.New("独立备份目录须为当前执行器所有的0700普通目录")
	}
	child, err := d.OpenRoot(name)
	if err != nil {
		return err
	}
	opened, err := child.Stat(".")
	parent, parentErr := d.Stat(".")
	if err != nil || parentErr != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, true, false) || opened.Sys().(*syscall.Stat_t).Dev != parent.Sys().(*syscall.Stat_t).Dev {
		child.Close()
		return errors.New("独立备份目录打开期间变化或跨越文件系统")
	}
	d.Root = child
	d.roots = append(d.roots, child)
	d.paths = append(d.paths, filepath.Join(d.paths[len(d.paths)-1], name))
	if !d.current() {
		return errors.New("独立备份目录不再是原路径")
	}
	return nil
}
func remoteCopySync(d *modulePrivateDirectory) error {
	if !d.current() {
		return errors.New("独立备份刷盘前目录变化")
	}
	f, err := d.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return err
	}
	if !d.current() {
		return errors.New("独立备份刷盘后目录变化")
	}
	return nil
}
func remoteCopyEntries(d *modulePrivateDirectory, maximum int) ([]os.DirEntry, error) {
	if !d.current() {
		return nil, errors.New("独立备份目录变化")
	}
	f, err := d.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maximum || !d.current() {
		return nil, errors.New("独立备份库存超限或读取期间变化")
	}
	return entries, nil
}
func remoteCopyMetadata(d *modulePrivateDirectory, name string, out any) ([]byte, error) {
	info, err := d.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > remoteCopyRecordLimit || !d.current() {
		return nil, errors.New("独立备份记录身份、权限或容量异常")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) || !moduleRecordInfo(opened, false, false) {
		return nil, errors.New("独立备份记录打开期间变化")
	}
	raw, err := io.ReadAll(io.LimitReader(f, remoteCopyRecordLimit+1))
	after, afterErr := f.Stat()
	visible, visibleErr := d.Lstat(name)
	if err != nil || afterErr != nil || visibleErr != nil || int64(len(raw)) != info.Size() || !programQueueSame(info, after) || !programQueueSame(info, visible) || !d.current() {
		return nil, errors.New("独立备份记录读取期间变化")
	}
	// Every record is produced by this fixed writer. Exact canonical bytes also
	// reject duplicate/escaped/case-folded keys, unknown fields and extra JSON.
	if json.Unmarshal(raw, out) != nil {
		return nil, errors.New("独立备份原记录不完整，保留且不自动覆盖")
	}
	canonical, err := json.MarshalIndent(out, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return nil, errors.New("独立备份原记录不是固定完整格式，保留且不自动覆盖")
	}
	return raw, nil
}
func remoteCopyTemporary(name string) bool {
	return strings.HasPrefix(name, "record-") && strings.HasSuffix(name, ".part") && core.ValidID(strings.TrimSuffix(strings.TrimPrefix(name, "record-"), ".part"))
}
func remoteCopyPublish(d *modulePrivateDirectory, name string, value any) ([]byte, error) {
	if name != "intent.json" && name != "attempt.json" && name != "result.json" && name != "retained.json" && name != remoteUnpublishedReceipt || !d.current() {
		return nil, errors.New("独立备份记录名称或目录无效")
	}
	if _, err := d.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("独立备份原记录已存在或不能核对，未覆盖")
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil || int64(len(raw))+1 > remoteCopyRecordLimit {
		return nil, errors.New("独立备份记录超过容量")
	}
	raw = append(raw, '\n')
	stage := "record-" + core.ID() + ".part"
	f, err := d.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || !d.current() {
		return nil, errors.New("独立备份记录持久化失败；原片段保留")
	}
	if err = renameNoReplace(d.Root, stage, name); err != nil {
		return nil, err
	}
	if err = remoteCopySync(d); err != nil {
		return nil, err
	}
	return raw, nil
}
