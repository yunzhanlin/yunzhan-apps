//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A deliberately closed, proven-unstarted request keeps a durable tombstone.
// A delayed original HTTP dispatch must see this before touching the log;
// merely not finding an archive in one browser observation is insufficient.
type apacheCCArchiveClosed struct {
	Format  int                         `json:"format"`
	State   string                      `json:"state"`
	At      string                      `json:"at"`
	Request core.ApacheCCArchiveRequest `json:"request"`
}

func (s *Service) apacheCCArchiveClosedDirectory() string {
	return filepath.Join(s.moduleDir("apache-waf"), "cc-log-closed-requests")
}

func (s *Service) readApacheCCArchiveClosed(id string) (apacheCCArchiveClosed, string, error) {
	var out apacheCCArchiveClosed
	if !core.ValidID(id) {
		return out, "", errors.New("CC 原关闭请求标识无效")
	}
	if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveClosedDirectory(), false); err != nil {
		return out, "", err
	}
	digest, err := readApacheCCArchivePhase(filepath.Join(s.apacheCCArchiveClosedDirectory(), id+".json"), &out)
	if err != nil {
		return out, "", err
	}
	if out.Format != 1 || out.State != "closed-before-archive" || !validApacheNumericRotationTime(out.At) || out.Request.RequestID != id || out.Request.ExpectedRevision < 1 || out.Request.ExpectedRevision > 1000000000 {
		return out, "", errors.New("CC 原关闭记录身份不可核对，未自动重发请求")
	}
	return out, digest, nil
}

func (s *Service) apacheCCArchiveClosedInventory(ctx context.Context) ([]apacheCCArchiveClosed, error) {
	out := []apacheCCArchiveClosed{}
	dir := s.apacheCCArchiveClosedDirectory()
	if err := s.apacheNumericLogPrivateDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	entries, err := apacheCCArchiveDirectoryEntries(dir, 128)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !core.ValidID(id) || entry.IsDir() {
			return nil, errors.New("CC 原关闭库存有未知条目，未忽略")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, _, err := s.readApacheCCArchiveClosed(id)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

// Caller owns the genuine exclusive WAF configuration descriptor. The absence
// check and tombstone commit share that lock with all original archive calls.
func (s *Service) closeUnstartedApacheCCArchiveUnderLock(ctx context.Context, lock *os.File, in core.ApacheCCArchiveRequest) (apacheCCArchiveClosed, error) {
	var empty apacheCCArchiveClosed
	if !core.ValidID(in.RequestID) || in.ExpectedRevision < 1 || in.ExpectedRevision > 1000000000 {
		return empty, errors.New("CC 原请求参数无效")
	}
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	prior, _, err := s.readApacheCCArchiveClosed(in.RequestID)
	if err == nil {
		if prior.Request != in {
			return empty, errors.New("CC 原关闭标识对应的参数不同")
		}
		return prior, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	// Even an empty or broken directory is an original started operation.
	// Never erase it, complete it, or disguise it as an unstarted request.
	if _, _, err := s.apacheCCArchiveEntryDirectory(in.RequestID); !errors.Is(err, os.ErrNotExist) {
		return empty, errors.New("CC 原请求已有归档证据，不能按未开始关闭")
	}
	entries, err := s.apacheCCArchiveClosedInventory(ctx)
	if err != nil {
		return empty, err
	}
	if len(entries) >= 128 {
		return empty, errors.New("CC 原关闭记录达到 128 份，未删除历史")
	}
	dir := s.apacheCCArchiveClosedDirectory()
	if err := s.apacheNumericLogPrivateDirectory(dir, true); err != nil {
		return empty, err
	}
	out := apacheCCArchiveClosed{Format: 1, State: "closed-before-archive", At: core.Now(), Request: in}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return empty, err
	}
	f, err := os.OpenFile(filepath.Join(dir, in.RequestID+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return empty, err
	}
	n, writeErr := f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(raw)+1 || syncErr != nil || closeErr != nil {
		return empty, errors.New("CC 原关闭记录未确认持久化，原记录保留，不自动重发")
	}
	if err := apacheNumericLogSyncDirectory(dir); err != nil {
		return empty, err
	}
	return out, nil
}
