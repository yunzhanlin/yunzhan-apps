//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// All indices, copies and full digests are checked, including snapshots the
// policy protects. A corrupt protected copy cannot hide behind an old candidate.
func (s *Service) wafBodyRetentionInventory(ctx context.Context) ([]wafBodyRetentionIdentity, error) {
	stages, err := s.wafBodyLogIndexStages(ctx)
	if err != nil || len(stages) != 0 {
		return nil, errors.New("存在未提交快照索引；未自动清理")
	}
	pending, err := s.wafBodyLogRecoveryEntries(ctx)
	if err != nil || len(pending) != 0 {
		return nil, errors.New("快照摘要异常或存在未完成事务；未自动清理")
	}
	entries, err := s.wafBodyLogArchives()
	if err != nil {
		return nil, err
	}
	out := []wafBodyRetentionIdentity{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.State != "completed" {
			return nil, errors.New("未知快照证据保留；未自动清理")
		}
		current, indexSHA, err := s.readWAFBodyLogIndex(entry.ID)
		if err != nil || current != entry {
			return nil, errors.New("快照索引身份发生变化")
		}
		f, err := s.openWAFBodyLogArchive(entry.ID)
		if err != nil {
			return nil, err
		}
		info, statErr := f.Stat()
		f.Close()
		if statErr != nil {
			return nil, statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.ModTime().UnixNano() <= 0 {
			return nil, errors.New("快照 inode 归属或时间异常")
		}
		actual, err := wafNativeFileSHA(ctx, filepath.Join(s.wafBodyLogArchiveDirectory(), entry.ID+".log"), wafBodyLogLimit)
		after, statErr := os.Lstat(filepath.Join(s.wafBodyLogArchiveDirectory(), entry.ID+".log"))
		if err != nil || statErr != nil || actual != entry.SHA256 || !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() || info.Mode() != after.Mode() {
			return nil, errors.New("快照摘要或 inode 核对期间变化；未删除")
		}
		out = append(out, wafBodyRetentionIdentity{Archive: entry, IndexSHA256: indexSHA, Device: uint64(stat.Dev), Inode: stat.Ino, MtimeNano: info.ModTime().UnixNano(), UID: stat.Uid, GID: stat.Gid})
	}
	return out, nil
}

func retentionInventoryMatches(actual []wafBodyRetentionIdentity, plan wafBodyRetentionDeletePlan, deleted []string) bool {
	removed := map[string]bool{}
	for _, id := range deleted {
		removed[id] = true
	}
	expected := []wafBodyRetentionIdentity{}
	for _, item := range plan.Inventory {
		if !removed[item.Archive.ID] {
			expected = append(expected, item)
		}
	}
	if len(expected) != len(actual) {
		return false
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}
