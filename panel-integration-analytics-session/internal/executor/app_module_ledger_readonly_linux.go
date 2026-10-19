//go:build linux

package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func (s *Service) openModuleLedgerReadOnly(ctx context.Context, id string) (*sql.DB, *modulePrivateDirectory, *os.File, os.FileInfo, error) {
	dir, err := s.moduleRecordDirectory(id)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var pinned *os.File
	fail := func(err error) (*sql.DB, *modulePrivateDirectory, *os.File, os.FileInfo, error) {
		if pinned != nil {
			pinned.Close()
		}
		dir.Close()
		return nil, nil, nil, nil, err
	}
	info, err := dir.Lstat("history.sqlite")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !dir.current() {
			err = errors.New("历史数据库目录变化，未按空历史返回")
		}
		return fail(err)
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 100 || info.Size() > 128<<20 {
		return fail(errors.New("历史数据库类型、身份、权限、链接数或容量异常"))
	}
	// A writer must recover its own interrupted transaction. A read request
	// must not delete journal evidence or silently discard WAL contents.
	for _, name := range []string{"history.sqlite-journal", "history.sqlite-wal", "history.sqlite-shm"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return fail(errors.New("历史数据库有事务侧文件，须核对原写入任务；只读查询未恢复或删除文件"))
		}
	}
	pinned, err = dir.OpenFile("history.sqlite", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(errors.New("历史数据库打开期间变化"))
	}
	opened, err := pinned.Stat()
	if err != nil || !os.SameFile(info, opened) || !moduleRecordInfo(opened, false, false) || !dir.current() {
		return fail(errors.New("历史数据库打开身份变化"))
	}
	// The SQLite connection itself is mode=ro. Keep the verified descriptor
	// and complete private ancestry alive and check identity/content metadata
	// again before returning. This does not claim protection from hostile root
	// code that can replace the named SQLite path concurrently.
	u := url.URL{Scheme: "file", Path: filepath.Join(s.moduleDir(id), "history.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return fail(err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, `PRAGMA busy_timeout=2000; PRAGMA query_only=ON;`); err != nil {
		db.Close()
		return fail(errors.New("历史数据库只读打开失败；未修复或覆盖"))
	}
	if !moduleLedgerReadUnchanged(dir, pinned, info) {
		db.Close()
		return fail(errors.New("历史数据库连接期间身份或内容变化"))
	}
	return db, dir, pinned, info, nil
}

func moduleLedgerReadUnchanged(dir *modulePrivateDirectory, pinned *os.File, before os.FileInfo) bool {
	after, err := pinned.Stat()
	visible, visibleErr := dir.Lstat("history.sqlite")
	if err != nil || visibleErr != nil || !os.SameFile(before, after) || !os.SameFile(before, visible) || before.Size() != after.Size() || before.Size() != visible.Size() || before.ModTime() != after.ModTime() || before.ModTime() != visible.ModTime() || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(visible, false, false) || !dir.current() {
		return false
	}
	for _, name := range []string{"history.sqlite-journal", "history.sqlite-wal", "history.sqlite-shm"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func validateModuleLedgerEvent(event moduleEvent) error {
	if _, err := time.Parse(time.RFC3339, event.Time); err != nil {
		return errors.New("历史摘要时间无效")
	}
	if len(event.ID) != 32 || strings.IndexFunc(event.ID, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0 || event.Action == "" || len(event.Action) > 80 || event.Trigger == "" || len(event.Trigger) > 40 || len(event.Error) > 516 || event.Outcome != "succeeded" && event.Outcome != "failed" && event.Outcome != "conflicts" || event.Copied < 0 || event.Conflicts < 0 || event.Changes < 0 || event.Restored < 0 || event.Findings < 0 || event.Quarantined < 0 {
		return errors.New("历史摘要身份、状态或计数无效")
	}
	return nil
}

func readLegacyModuleHistory(in core.AppModuleInput, legacy []moduleEvent) (any, error) {
	if len(legacy) > 100 {
		return nil, errors.New("旧历史摘要超过 100 条，未部分返回")
	}
	from, _ := time.Parse(time.RFC3339, in.FromTime)
	to, _ := time.Parse(time.RFC3339, in.ToTime)
	filtered := []moduleEvent{}
	for i := len(legacy) - 1; i >= 0; i-- {
		event := legacy[i]
		if err := validateModuleLedgerEvent(event); err != nil {
			return nil, err
		}
		at, _ := time.Parse(time.RFC3339, event.Time)
		raw, err := json.Marshal(event)
		if err != nil || len(raw) > 4096 {
			return nil, errors.New("旧历史摘要超过安全容量")
		}
		if in.SiteID != "" && event.SiteID != in.SiteID || in.ResourceID != "" && event.ResourceID != in.ResourceID || !from.IsZero() && at.Before(from) || !to.IsZero() && at.After(to) || in.Search != "" && !strings.Contains(strings.ToLower(string(raw)), strings.ToLower(in.Search)) {
			continue
		}
		filtered = append(filtered, event)
	}
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	start := in.Offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return map[string]any{"history": filtered[start:end], "total": len(filtered), "retained_count": len(legacy), "limit": limit, "offset": in.Offset, "retention_days": moduleHistoryRetention, "record_limit": moduleHistoryRows, "history_limited": len(filtered) > end-start, "read_only": true, "source": "legacy-json", "scope": "只读旧版最多 100 条摘要；未创建数据库、导入、修剪或重写原文件。下一次实际保存摘要时再迁移。"}, nil
}
