//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
)

// The caller holds the real shared observation lock. A selected, verified
// copy remains exportable even when another copy makes the full inventory
// incomplete. Read-only export never resolves an uncertain deletion outcome.
func (s *Service) exportWAFBodyLogArchive(ctx context.Context, entry wafBodyLogArchive, indexSHA string) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !core.ValidID(entry.ID) || !wafLogDigestValid(indexSHA) {
		return nil, errors.New("所选快照或索引摘要无效")
	}
	if entry.State == "copying" {
		return nil, errors.New("所选快照复制未确认完成；请先导出恢复意图并核对，未当成完整快照")
	}
	f, err := s.openWAFBodyLogArchive(entry.ID)
	if entry.State == "retained-missing" {
		if f != nil {
			f.Close()
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("原缺失快照的实际缺失状态变化；未导出空记录")
		}
		return map[string]any{"archive": entry, "metadata": core.WAFBodyEventsPage{Events: []core.WAFBodyEvent{}, BestEffort: true}, "export_contract": "missing_snapshot_intent_only_no_rule_events_available"}, nil
	}
	if err != nil {
		return nil, errors.New("所选快照实际文件不可核验；请查看恢复意图，未当成空快照")
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || before.Size() != entry.Bytes {
		return nil, errors.New("所选快照大小与原索引不符，未导出")
	}
	path := filepath.Join(s.wafBodyLogArchiveDirectory(), entry.ID+".log")
	sha, err := wafNativeFileSHA(ctx, path, wafBodyLogLimit)
	if err != nil || sha != entry.SHA256 {
		return nil, errors.New("所选快照摘要核对失败，未导出")
	}
	page, err := readWAFBodyEventsFile(f, false)
	if err != nil {
		return nil, err
	}
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	latest, latestSHA, indexErr := s.readWAFBodyLogIndex(entry.ID)
	sha, digestErr := wafNativeFileSHA(ctx, path, wafBodyLogLimit)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if statErr != nil || pathErr != nil || indexErr != nil || digestErr != nil ||
		!os.SameFile(before, after) || !os.SameFile(before, current) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		latest != entry || latestSHA != indexSHA || sha != entry.SHA256 {
		return nil, errors.New("所选快照或索引在导出期间变化，未导出")
	}
	return map[string]any{"archive": entry, "metadata": page, "export_contract": "numeric_only_recent_4MiB_5000_rules_not_full_raw_archive", "selected_snapshot_digest_verified": true, "inventory_not_claimed_complete": true}, nil
}
