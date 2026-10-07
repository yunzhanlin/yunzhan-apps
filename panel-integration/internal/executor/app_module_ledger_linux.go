//go:build linux

package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const moduleHistoryRetention = 365
const moduleHistoryRows = 100000

// The ledger contains only moduleEvent summaries, never operation inputs or
// result bodies. Keep the old JSON ring for downgrade compatibility, while
// preserving earlier summaries in this bounded, indexed private database.
func (s *Service) openModuleLedger(ctx context.Context, id string) (*sql.DB, error) {
	if _, ok := core.FindAppModule(id); !ok {
		return nil, errors.New("未知历史模块")
	}
	dir := s.moduleDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for _, path := range []string{s.Config.SecurityDir, filepath.Join(s.Config.SecurityDir, "modules"), dir} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
			return nil, errors.New("历史目录不安全，未创建或修改记录")
		}
	}
	path := filepath.Join(dir, "history.sqlite")
	created, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDONLY|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		err = created.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	for _, name := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && name != path {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
			return nil, errors.New("历史数据库路径或权限不安全，拒绝打开")
		}
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.ExecContext(ctx, `PRAGMA busy_timeout=2000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=32768;
CREATE TABLE IF NOT EXISTS module_events(seq INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,site_id TEXT NOT NULL,resource_id TEXT NOT NULL,payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS module_events_site ON module_events(site_id,seq DESC);
CREATE INDEX IF NOT EXISTS module_events_resource ON module_events(resource_id,seq DESC);
CREATE INDEX IF NOT EXISTS module_events_time ON module_events(created_at);
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, errors.New("历史数据库损坏或不可写，未覆盖旧记录")
	}
	return db, nil
}

func insertModuleLedgerEvent(ctx context.Context, tx *sql.Tx, event moduleEvent) error {
	at, err := time.Parse(time.RFC3339, event.Time)
	if err != nil || !core.ValidID(event.ID) || len(event.Error) > 516 || len(event.Action) > 80 || len(event.Trigger) > 40 {
		return errors.New("历史摘要格式损坏，未导入")
	}
	raw, err := json.Marshal(event)
	if err != nil || len(raw) > 4096 {
		return errors.New("历史摘要超过安全上限")
	}
	// Keep sequence numbers monotonic even if retention removes every row.
	// Consumers use this cursor across process restarts and idle periods.
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO module_events(seq,event_id,created_at,site_id,resource_id,payload)
SELECT MAX(COALESCE((SELECT MAX(seq) FROM module_events),0),COALESCE((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='last-event-sequence'),0))+1,?,?,?,?,?`, event.ID, at.Unix(), event.SiteID, event.ResourceID, string(raw))
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value) SELECT 'last-event-sequence',CAST(COALESCE(MAX(seq),0) AS TEXT) FROM module_events WHERE 1 ON CONFLICT(key) DO UPDATE SET value=CAST(MAX(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)`)
	}
	return err
}

func (s *Service) saveModuleLedger(id string, legacy []moduleEvent, event *moduleEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := s.openModuleLedger(ctx, id)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var imported string
	err = tx.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='legacy-imported'`).Scan(&imported)
	if errors.Is(err, sql.ErrNoRows) {
		if len(legacy) > 100 {
			return errors.New("旧历史摘要超过上限，未覆盖")
		}
		for _, old := range legacy {
			if err := insertModuleLedgerEvent(ctx, tx, old); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO metadata VALUES('legacy-imported','1')`)
	}
	if err != nil {
		return err
	}
	if event != nil {
		if err = insertModuleLedgerEvent(ctx, tx, *event); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM module_events WHERE created_at<?`, time.Now().AddDate(0, 0, -moduleHistoryRetention).Unix())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM module_events WHERE seq <= COALESCE((SELECT seq FROM module_events ORDER BY seq DESC LIMIT 1 OFFSET ?),-1)`, moduleHistoryRows)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) readModuleLedger(id string, in core.AppModuleInput, legacy []moduleEvent) (any, error) {
	if err := core.ValidateModuleHistoryInput(in); err != nil {
		return nil, err
	}
	if err := s.saveModuleLedger(id, legacy, nil); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := s.openModuleLedger(ctx, id)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	where, args := []string{"1=1"}, []any{}
	for _, filter := range []struct{ column, value string }{{"site_id", in.SiteID}, {"resource_id", in.ResourceID}} {
		if filter.value != "" {
			where = append(where, filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	for _, filter := range []struct{ operator, value string }{{">=", in.FromTime}, {"<=", in.ToTime}} {
		if filter.value != "" {
			at, _ := time.Parse(time.RFC3339, filter.value)
			where = append(where, "created_at"+filter.operator+"?")
			args = append(args, at.Unix())
		}
	}
	if in.Search != "" {
		where = append(where, `payload LIKE ? ESCAPE '\'`)
		literal := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(in.Search)
		args = append(args, "%"+literal+"%")
	}
	clause := strings.Join(where, " AND ")
	var count, retained int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM module_events WHERE `+clause, args...).Scan(&count); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM module_events`).Scan(&retained); err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	queryArgs := append(append([]any{}, args...), limit, in.Offset)
	rows, err := db.QueryContext(ctx, `SELECT payload FROM module_events WHERE `+clause+` ORDER BY seq DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []moduleEvent{}
	for rows.Next() {
		var raw string
		var event moduleEvent
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(raw) > 4096 || json.Unmarshal([]byte(raw), &event) != nil {
			return nil, errors.New("历史摘要损坏，拒绝返回错误记录")
		}
		events = append(events, event)
	}
	return map[string]any{"history": events, "total": count, "retained_count": retained, "limit": limit, "offset": in.Offset, "retention_days": moduleHistoryRetention, "record_limit": moduleHistoryRows, "history_limited": count > len(events), "scope": "私有数据库保留最近 365 天、最多 100000 条操作摘要；可按网站、计划、时间和关键词筛选分页。不保存密码、令牌或完整请求正文。旧版 JSON 摘要保留用于回退。"}, rows.Err()
}
