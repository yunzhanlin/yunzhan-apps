//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"syscall"
)

type wafBodyLogIndexStage struct {
	ID     string `json:"id"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Staging lives outside the strict snapshot inventory. A killed atomic writer
// can leave even a zero-byte index; it is evidence, never a committed intent.
// Fixed ID paths, private ownership and a quota permit explicit preservation
// without importing arbitrary files or interpreting partial JSON as success.
func (s *Service) wafBodyLogIndexDirectory() string {
	return s.systemPath("/var/lib/panel-waf/index-staging")
}

func (s *Service) wafBodyLogPrivateDirectory(path string, create bool) error {
	_, before := os.Lstat(path)
	created := errors.Is(before, os.ErrNotExist)
	if err := s.wafOwnedDirectory(path, create); err != nil {
		return err
	}
	if created && create {
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0700 {
		return errors.New("已有日志私有目录权限不匹配，未修复或接管")
	}
	return nil
}

func wafBodyLogSyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Service) readWAFBodyLogIndexStage(ctx context.Context, id string) (wafBodyLogIndexStage, os.FileInfo, error) {
	var out wafBodyLogIndexStage
	if !core.ValidID(id) {
		return out, nil, errors.New("索引残件标识无效")
	}
	path := filepath.Join(s.wafBodyLogIndexDirectory(), id+".json")
	if err := ownedRuntimePath(path, false); err != nil {
		return out, nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1024 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		return out, nil, errors.New("索引残件权限、类型或大小异常，未接管")
	}
	if err := ctx.Err(); err != nil {
		return out, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(data) > 1024 {
		return out, nil, errors.New("索引残件不可有界读取")
	}
	hash := sha256.Sum256(data)
	return wafBodyLogIndexStage{ID: id, Bytes: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}, st, nil
}

func (s *Service) wafBodyLogIndexStages(ctx context.Context) ([]wafBodyLogIndexStage, error) {
	out := []wafBodyLogIndexStage{}
	directory := s.wafBodyLogIndexDirectory()
	if err := s.wafBodyLogPrivateDirectory(directory, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) > wafBodyLogArchiveLimit {
		return nil, errors.New("索引残件目录异常或超出固定上限")
	}
	for _, file := range files {
		name := file.Name()
		if len(name) != 37 || name[32:] != ".json" || !core.ValidID(name[:32]) || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("索引暂存目录存在未知条目，未自动接管")
		}
		entry, _, err := s.readWAFBodyLogIndexStage(ctx, name[:32])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *Service) writeWAFBodyLogIndex(ctx context.Context, entry wafBodyLogArchive) error {
	return s.writeWAFBodyLogIndexAt(ctx, entry, nil)
}

// All production callers already hold the WAF cross-process lock. No random
// generic atomic-write temporary file can strand the snapshot directory.
func (s *Service) writeWAFBodyLogIndexAt(ctx context.Context, entry wafBodyLogArchive, checkpoint func(string) error) error {
	if !core.ValidID(entry.ID) {
		return errors.New("元数据索引标识无效")
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	directory := s.wafBodyLogIndexDirectory()
	if err := s.wafBodyLogPrivateDirectory(directory, true); err != nil {
		return err
	}
	pending, err := s.wafBodyLogIndexStages(ctx)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("存在未提交索引残件，请先按摘要保留证据；当前日志未动")
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil || len(data) > 1024 {
		return errors.New("元数据索引编码超过上限")
	}
	stage := filepath.Join(directory, entry.ID+".json")
	f, err := os.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close() // On error, retain the exact partial file, never auto-delete.
	if err := mark("index-stage-created"); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := mark("index-stage-written"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := wafBodyLogSyncDirectory(directory); err != nil {
		return err
	}
	if err := mark("index-stage-durable"); err != nil {
		return err
	}
	index := filepath.Join(s.wafBodyLogArchiveDirectory(), entry.ID+".json")
	if err := ownedRuntimePath(index, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(stage, index); err != nil {
		return err
	}
	// Both directory entries are durable before any live-log truncate/unlink.
	if err := wafBodyLogSyncDirectory(s.wafBodyLogArchiveDirectory()); err != nil {
		return err
	}
	if err := wafBodyLogSyncDirectory(directory); err != nil {
		return err
	}
	return mark("index-renamed-durable")
}

// Recover a partial atomic write by preserving its exact inode in a separate
// private directory. It is not installed as an index or treated as a snapshot.
// Moving only this digest-bound ID is reversible, and does not delete evidence.
func (s *Service) retainWAFBodyLogIndexStage(ctx context.Context, id, sha string) (string, error) {
	if !core.ValidID(id) || !wafLogDigestValid(sha) {
		return "", errors.New("索引残件标识或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if _, err := s.wafBodyLogIndexStages(ctx); err != nil {
		return "", err
	}
	entry, before, err := s.readWAFBodyLogIndexStage(ctx, id)
	if err != nil {
		return "", err
	}
	if entry.SHA256 != sha {
		return "", errors.New("索引残件摘要变化，未移动")
	}
	directory := s.systemPath("/var/lib/panel-waf/retained-index-staging")
	if err := s.wafBodyLogPrivateDirectory(directory, true); err != nil {
		return "", err
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) >= 100 {
		return "", errors.New("索引残件证据已达100份，请先人工归档；未丢弃证据")
	}
	retained := core.ID()
	to := filepath.Join(directory, retained+".json")
	if _, err := os.Lstat(to); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("证据标识冲突，未覆盖")
	}
	from := filepath.Join(s.wafBodyLogIndexDirectory(), id+".json")
	current, err := os.Lstat(from)
	if err != nil || !os.SameFile(before, current) {
		return "", errors.New("索引残件路径已替换，未移动")
	}
	// Persist provenance first. A failure may leave a duplicate audit record,
	// but cannot discard the only copy or alter a committed index/current log.
	audit := filepath.Join(s.Config.SecurityDir, "waf-log-recovery")
	if err := s.wafBodyLogPrivateDirectory(audit, true); err != nil {
		return "", err
	}
	auditFiles, err := os.ReadDir(audit)
	if err != nil || len(auditFiles) >= 100 {
		return "", errors.New("恢复审计证据配额已满，未移动")
	}
	if err := moduleWrite(filepath.Join(audit, retained+".json"), map[string]any{"created_at": core.Now(), "uncommitted_index": entry, "retained_id": retained, "never_applied_as_index": true, "current_log_untouched": true}); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.Rename(from, to); err != nil {
		return "", err
	}
	if err := wafBodyLogSyncDirectory(directory); err != nil {
		return "", err
	}
	if err := wafBodyLogSyncDirectory(s.wafBodyLogIndexDirectory()); err != nil {
		return "", err
	}
	return retained, nil
}
