//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const apacheCCArchiveHistoryCount = 32

func (s *Service) apacheCCArchiveHistoryDirectory() string {
	return s.systemPath("/var/lib/panel-apache-body/cc-archive-history")
}

// Both namespaces are fixed Root-owned directories. An ID remains reserved
// after transfer: it is never made available for a delayed archive request.
// Duplicate locations or foreign parents are errors, not a preferred copy.
func (s *Service) apacheCCArchiveEntryDirectory(id string) (string, bool, error) {
	if !core.ValidID(id) {
		return "", false, errors.New("CC 原归档标识无效")
	}
	found, history := "", false
	for i, base := range []string{s.apacheCCArchiveDirectory(), s.apacheCCArchiveHistoryDirectory()} {
		if err := s.apacheNumericLogPrivateDirectory(base, false); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", false, err
		}
		path := filepath.Join(base, id)
		if err := s.apacheNumericLogPrivateDirectory(path, false); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", false, err
		}
		if found != "" {
			return "", false, errors.New("CC 原标识同时出现在两处，未选择或删除任何副本")
		}
		found, history = path, i == 1
	}
	if found == "" {
		return "", false, os.ErrNotExist
	}
	return found, history, nil
}

// Transfer only a digest-bound complete directory; every original inode,
// phase file, incomplete retention fragment and byte moves together. There is
// no copy/truncate, unlink, Apache reload or change to the active log. An
// interrupted response is observed by its original ID across both locations.
func (s *Service) preserveApacheCCArchiveHistoryUnderLock(ctx context.Context, lock *os.File, id, expectedSHA string, checkpoint func(string) error) (apacheCCArchiveEntry, error) {
	var empty apacheCCArchiveEntry
	if !wafLogDigestValid(expectedSHA) {
		return empty, errors.New("CC 原历史转存摘要无效")
	}
	if err := s.verifyApacheNumericLock(lock); err != nil {
		return empty, err
	}
	entry, err := s.readApacheCCArchive(ctx, id)
	if err != nil {
		return empty, err
	}
	if entry.State != "completed" && entry.State != "retained-unknown" {
		return empty, errors.New("CC 原结果尚未完整保留，未转存或清理")
	}
	snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
	if err != nil {
		return empty, err
	}
	if apacheCCArchiveSnapshotSHA(snapshot) != expectedSHA {
		return empty, errors.New("CC 原始文件清单已变化，未转存")
	}
	dir, history, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		return empty, err
	}
	if history {
		return entry, nil
	} // Read-only original outcome, never rename again.
	rows, err := s.apacheCCArchiveHistoryInventory(ctx)
	if err != nil {
		return empty, err
	}
	if len(rows) >= apacheCCArchiveHistoryCount {
		return empty, errors.New("CC 历史保留达到 32 份，原文件未删除或覆盖")
	}
	mark := func(stage string) error {
		if checkpoint != nil {
			return checkpoint(stage)
		}
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := mark("original-history-snapshot-verified"); err != nil {
		return empty, err
	}
	if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveHistoryDirectory(), true); err != nil {
		return empty, err
	}
	parent, err := os.OpenFile(s.apacheCCArchiveDirectory(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	defer parent.Close()
	destination, err := os.OpenFile(s.apacheCCArchiveHistoryDirectory(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	defer destination.Close()
	// The target is never overwritten, even if a duplicate appears after the
	// initial inventory. No non-atomic cross-filesystem fallback is permitted.
	if filepath.Dir(dir) != s.apacheCCArchiveDirectory() {
		return empty, errors.New("CC 原归档位置已变化")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := unix.Renameat2(int(parent.Fd()), id, int(destination.Fd()), id, unix.RENAME_NOREPLACE); err != nil {
		return empty, err
	}
	if err := mark("history-directory-moved"); err != nil {
		return empty, err
	}
	if err := parent.Sync(); err != nil {
		return empty, err
	}
	if err := destination.Sync(); err != nil {
		return empty, err
	}
	if err := mark("history-directories-durable"); err != nil {
		return empty, err
	}
	observed, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
	if err != nil {
		return empty, err
	}
	if apacheCCArchiveSnapshotSHA(observed) != expectedSHA {
		return empty, errors.New("CC 转存后原始文件清单不符，请按原标识只读核对")
	}
	return s.readApacheCCArchive(ctx, id)
}
