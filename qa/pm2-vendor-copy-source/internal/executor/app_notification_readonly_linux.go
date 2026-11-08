//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"local/panel/internal/core"
	"os"
	"strconv"
	"time"
)

// Readers never initialize/migrate a ledger, recover its journal, trim events
// or wait behind unrelated native service mutations. The existing writer owns
// all migration and retention. A concurrent write invalidates this observation
// rather than returning a partial page or advancing a speculative cursor.
func (s *Service) moduleAlertPage(ctx context.Context, id string, cursor int64) (core.ModuleAlertPage, error) {
	page := core.ModuleAlertPage{Cursor: cursor, Events: []core.ModuleAlertEvent{}}
	if page.Cursor < 0 {
		page.Cursor = 0
	}
	guard, installed, err := s.beginModuleAlertRead(id)
	if err != nil || !installed {
		return page, err
	}
	defer guard.dir.Close()
	db, directory, pinned, before, err := s.openModuleLedgerReadOnly(ctx, id)
	if errors.Is(err, os.ErrNotExist) {
		for _, name := range []string{"history.sqlite", "history.sqlite-journal", "history.sqlite-wal", "history.sqlite-shm"} {
			if _, e := guard.dir.Lstat(name); !errors.Is(e, os.ErrNotExist) {
				return page, errors.New("告警历史或事务侧文件出现，未创建或恢复数据库")
			}
		}
		legacy := []moduleEvent{}
		if e := s.moduleRetrospectiveRecord(id, "history.json", &legacy); e != nil && !errors.Is(e, os.ErrNotExist) {
			return page, e
		}
		if len(legacy) != 0 || cursor > 0 {
			return page, errors.New("原告警历史尚无可核对的数据库序列，保留原游标；只读请求未迁移旧摘要")
		}
		return page, guard.check(ctx)
	}
	if err != nil {
		return page, err
	}
	defer directory.Close()
	defer pinned.Close()
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	var imported string
	err = tx.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='legacy-imported'`).Scan(&imported)
	if errors.Is(err, sql.ErrNoRows) {
		legacy := []moduleEvent{}
		if e := s.moduleRetrospectiveRecord(id, "history.json", &legacy); e != nil && !errors.Is(e, os.ErrNotExist) {
			return page, e
		}
		if len(legacy) != 0 {
			return page, errors.New("旧摘要尚未由原写入器完成迁移，未把已有空数据库当作零历史")
		}
	} else if err != nil || imported != "1" {
		return page, errors.New("原历史迁移状态无法核对，未重置游标")
	}
	var first, last, count int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(seq),0),COALESCE(MAX(seq),0),COUNT(*) FROM module_events`).Scan(&first, &last, &count); err != nil {
		return page, err
	}
	if count < 0 || count > moduleHistoryRows || count > 0 && (first < 1 || last < first) || count == 0 && (first != 0 || last != 0) {
		return page, errors.New("告警历史序列或保留数量无效")
	}
	var watermark string
	err = tx.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='last-event-sequence'`).Scan(&watermark)
	if errors.Is(err, sql.ErrNoRows) && last == 0 {
		watermark = "0"
	} else if err != nil {
		return page, errors.New("告警历史缺少原递增序列")
	}
	end, err := strconv.ParseInt(watermark, 10, 64)
	if err != nil || end < last || end < 0 || strconv.FormatInt(end, 10) != watermark {
		return page, errors.New("告警历史递增序列损坏，未重置游标")
	}
	last = end
	if cursor > last {
		return page, errors.New("应用历史序列回退，请核对数据库")
	}
	if cursor == -1 {
		page.Cursor = last
	} else {
		page.Gap = first > cursor && first-cursor > 1 || first == 0 && last > cursor
		rows, e := tx.QueryContext(ctx, `SELECT seq,event_id,created_at,payload FROM module_events WHERE seq>? ORDER BY seq LIMIT 500`, cursor)
		if e != nil {
			return page, e
		}
		defer rows.Close()
		for rows.Next() {
			var seq, created int64
			var eventID, raw string
			if err = rows.Scan(&seq, &eventID, &created, &raw); err != nil {
				return page, err
			}
			var decoded []moduleEvent
			if seq <= page.Cursor || seq > last || len(raw) > 4096 || decodeModuleRetrospectiveJSON([]byte("["+raw+"]"), &decoded, true) != nil || len(decoded) != 1 || validateModuleLedgerEvent(decoded[0]) != nil {
				return page, errors.New("应用告警摘要身份、序列或内容损坏")
			}
			event := decoded[0]
			at, _ := time.Parse(time.RFC3339, event.Time)
			if event.ID != eventID || at.Unix() != created {
				return page, errors.New("应用告警摘要与原数据库索引不一致")
			}
			page.Events = append(page.Events, core.ModuleAlertEvent{Sequence: seq, ID: event.ID, Time: event.Time, Outcome: event.Outcome, Changes: event.Changes, Conflicts: event.Conflicts, Findings: event.Findings, Quarantined: event.Quarantined, Restored: event.Restored})
			page.Cursor = seq
		}
		if err = rows.Err(); err != nil {
			return page, err
		}
		rows.Close()
		if len(page.Events) == 0 {
			page.Cursor = last
		}
	}
	if err = tx.Commit(); err != nil {
		return page, err
	}
	if !moduleLedgerReadUnchanged(directory, pinned, before) {
		return page, errors.New("应用告警历史在读取期间改变，未提交部分游标")
	}
	return page, guard.check(ctx)
}
