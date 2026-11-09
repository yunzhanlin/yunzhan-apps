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
	"strings"
	"syscall"
)

type apacheNumericLogIndexStage struct {
	ID     string `json:"id"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Staging lives outside the strict snapshot inventory. A killed atomic writer
// can leave even a zero-byte index; it is evidence, never a committed intent.
// Fixed ID paths, private ownership and a quota permit explicit preservation
// without importing arbitrary files or interpreting partial JSON as success.
func (s *Service) apacheNumericLogIndexDirectory() string {
	return s.systemPath("/var/lib/panel-apache-body/index-staging")
}

func (s *Service) apacheNumericLogPrivateDirectory(path string, create bool) error {
	return s.apacheNumericLogPrivateDirectoryAt(path, create, apacheNumericLogSyncDirectory)
}

// Only the private leaf may be created. Native installation or the existing
// Apache lock must already have established its owned parent. On every write,
// including a later attempt after failed fsync, commit both the private inode
// and its name in the parent before allowing any truncate or evidence move.
// The read-only upgrade fence never creates, repairs or syncs directories.
func (s *Service) apacheNumericLogPrivateDirectoryAt(path string, create bool, syncDirectory func(string) error) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("日志私有目录不是固定绝对路径")
	}
	parent := filepath.Dir(path)
	if err := s.wafOwnedDirectory(parent, false); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && create {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := s.wafOwnedDirectory(path, false); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0700 {
		return errors.New("已有日志私有目录权限不匹配，未修复或接管")
	}
	if create {
		if syncDirectory == nil {
			return errors.New("日志私有目录缺少实际持久化步骤")
		}
		if err := syncDirectory(path); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(st, current) || st.Mode() != current.Mode() {
			return errors.New("日志私有目录在持久化期间变化，未开始后续操作")
		}
	}
	return nil
}

func apacheNumericLogSyncDirectory(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// A readable interrupted write is not necessarily durable. Pin the original
// private data inode, sync its bytes, and verify the selected digest and path
// before committing retention provenance or moving it into retained history.
func (s *Service) syncApacheNumericLogEvidence(ctx context.Context, path, expectedSHA string) error {
	return s.syncApacheNumericLogEvidenceAt(ctx, path, expectedSHA, (*os.File).Sync)
}

func (s *Service) syncApacheNumericLogEvidenceAt(ctx context.Context, path, expectedSHA string, syncFile func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := filepath.Base(path)
	limit := int64(1024)
	valid := filepath.Dir(path) == s.apacheNumericLogIndexDirectory() && len(name) == 37 && strings.HasSuffix(name, ".json") && core.ValidID(name[:32])
	if filepath.Dir(path) == s.apacheNumericLogArchiveDirectory() && len(name) == 36 && strings.HasSuffix(name, ".log") && core.ValidID(name[:32]) {
		valid, limit = true, apacheNumericLogLimit
	}
	if !valid || !filepath.IsAbs(path) || filepath.Clean(path) != path || !wafLogDigestValid(expectedSHA) || syncFile == nil {
		return errors.New("证据持久化身份、固定路径或摘要无效")
	}
	if err := s.apacheNumericLogPrivateDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	if err := ownedRuntimePath(path, false); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 0 || before.Size() > limit {
		return errors.New("待保留证据类型、权限或容量异常")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("待保留证据所有权或链接数变化")
	}
	if err := syncFile(f); err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(&contextReader{ctx, f}, limit+1))
	if err != nil || n != before.Size() || n > limit || hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return errors.New("待保留证据持久化后摘要不符；未确认保留或移动")
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !apacheBodyEventsSameFile(before, after) || !apacheBodyEventsSameFile(after, current) {
		return errors.New("待保留证据在持久化核对期间变化")
	}
	return ctx.Err()
}

func (s *Service) readApacheNumericLogIndexStage(ctx context.Context, id string) (apacheNumericLogIndexStage, os.FileInfo, error) {
	var out apacheNumericLogIndexStage
	if !core.ValidID(id) {
		return out, nil, errors.New("索引残件标识无效")
	}
	path := filepath.Join(s.apacheNumericLogIndexDirectory(), id+".json")
	if err := ownedRuntimePath(path, false); err != nil {
		return out, nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
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
	return apacheNumericLogIndexStage{ID: id, Bytes: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}, st, nil
}

func (s *Service) apacheNumericLogIndexStages(ctx context.Context) ([]apacheNumericLogIndexStage, error) {
	out := []apacheNumericLogIndexStage{}
	directory := s.apacheNumericLogIndexDirectory()
	if err := s.apacheNumericLogPrivateDirectory(directory, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) > apacheNumericLogArchiveLimit {
		return nil, errors.New("索引残件目录异常或超出固定上限")
	}
	for _, file := range files {
		name := file.Name()
		if len(name) != 37 || name[32:] != ".json" || !core.ValidID(name[:32]) || file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("索引暂存目录存在未知条目，未自动接管")
		}
		entry, _, err := s.readApacheNumericLogIndexStage(ctx, name[:32])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *Service) writeApacheNumericLogIndex(ctx context.Context, entry apacheNumericLogArchive) error {
	return s.writeApacheNumericLogIndexAt(ctx, entry, nil)
}

// All production callers already hold the WAF cross-process lock. No random
// generic atomic-write temporary file can strand the snapshot directory.
func (s *Service) writeApacheNumericLogIndexAt(ctx context.Context, entry apacheNumericLogArchive, checkpoint func(string) error) error {
	if !core.ValidID(entry.ID) {
		return errors.New("元数据索引标识无效")
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return nil
	}
	directory := s.apacheNumericLogIndexDirectory()
	if err := s.apacheNumericLogPrivateDirectory(directory, true); err != nil {
		return err
	}
	pending, err := s.apacheNumericLogIndexStages(ctx)
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
	if err := apacheNumericLogSyncDirectory(directory); err != nil {
		return err
	}
	if err := mark("index-stage-durable"); err != nil {
		return err
	}
	index := filepath.Join(s.apacheNumericLogArchiveDirectory(), entry.ID+".json")
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
	if err := apacheNumericLogSyncDirectory(s.apacheNumericLogArchiveDirectory()); err != nil {
		return err
	}
	if err := apacheNumericLogSyncDirectory(directory); err != nil {
		return err
	}
	return mark("index-renamed-durable")
}

// Recover a partial atomic write by preserving its exact inode in a separate
// private directory. It is not installed as an index or treated as a snapshot.
// Moving only this digest-bound ID is reversible, and does not delete evidence.
func (s *Service) retainApacheNumericLogIndexStage(ctx context.Context, id, sha string) (string, error) {
	if !core.ValidID(id) || !wafLogDigestValid(sha) {
		return "", errors.New("索引残件标识或摘要无效")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if _, err := s.apacheNumericLogIndexStages(ctx); err != nil {
		return "", err
	}
	entry, before, err := s.readApacheNumericLogIndexStage(ctx, id)
	if err != nil {
		return "", err
	}
	if entry.SHA256 != sha {
		return "", errors.New("索引残件摘要变化，未移动")
	}
	if err := s.syncApacheNumericLogEvidence(ctx, filepath.Join(s.apacheNumericLogIndexDirectory(), id+".json"), sha); err != nil {
		return "", err
	}
	directory := s.systemPath("/var/lib/panel-apache-body/retained-index-staging")
	if err := s.apacheNumericLogPrivateDirectory(directory, true); err != nil {
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
	from := filepath.Join(s.apacheNumericLogIndexDirectory(), id+".json")
	current, err := os.Lstat(from)
	if err != nil || !os.SameFile(before, current) {
		return "", errors.New("索引残件路径已替换，未移动")
	}
	// Persist provenance first. A failure may leave a duplicate audit record,
	// but cannot discard the only copy or alter a committed index/current log.
	audit := filepath.Join(s.moduleDir("apache-waf"), "body-log-recovery")
	if err := s.apacheNumericLogPrivateDirectory(audit, true); err != nil {
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
	if err := apacheNumericLogSyncDirectory(directory); err != nil {
		return "", err
	}
	if err := apacheNumericLogSyncDirectory(s.apacheNumericLogIndexDirectory()); err != nil {
		return "", err
	}
	return retained, nil
}
