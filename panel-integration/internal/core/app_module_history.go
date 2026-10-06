package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *Store) recordAppModuleEvent(id, action, actor string, operationError error) error {
	outcome := "succeeded"
	if operationError != nil {
		outcome = "failed"
	}
	// Never persist operation inputs, output tokens or command errors here.
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO app_module_events(id,module_id,action,actor,outcome,created_at) VALUES(?,?,?,?,?,?)`, ID(), id, action, actor, outcome, Now()); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM app_module_events WHERE module_id=? AND created_at<?`, id, time.Now().AddDate(0, 0, -365).UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM app_module_events WHERE module_id=? AND rowid <= COALESCE((SELECT rowid FROM app_module_events WHERE module_id=? ORDER BY rowid DESC LIMIT 1 OFFSET 100000),-1)`, id, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) appModuleHistory(id string, filters ...AppModuleInput) (any, error) {
	in := AppModuleInput{}
	if len(filters) > 0 {
		in = filters[0]
	}
	if err := ValidateModuleHistoryInput(in); err != nil {
		return nil, err
	}
	if in.SiteID != "" || in.ResourceID != "" {
		return nil, errors.New("该模块的操作历史不包含网站或计划标识，请按时间与关键词筛选")
	}
	where, args := []string{"module_id=?"}, []any{id}
	for _, filter := range []struct{ operator, value string }{{">=", in.FromTime}, {"<=", in.ToTime}} {
		if filter.value != "" {
			at, _ := time.Parse(time.RFC3339, filter.value)
			where = append(where, "created_at"+filter.operator+"?")
			args = append(args, at.UTC().Format(time.RFC3339))
		}
	}
	if in.Search != "" {
		where = append(where, `(action LIKE ? ESCAPE '\' OR actor LIKE ? ESCAPE '\')`)
		literal := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(in.Search)
		args = append(args, "%"+literal+"%", "%"+literal+"%")
	}
	clause := strings.Join(where, " AND ")
	var total, retained int
	if err := s.DB.QueryRow(`SELECT count(*) FROM app_module_events WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, err
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM app_module_events WHERE module_id=?`, id).Scan(&retained); err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	queryArgs := append(append([]any{}, args...), limit, in.Offset)
	rows, err := s.DB.Query(`SELECT id,action,actor,outcome,created_at FROM app_module_events WHERE `+clause+` ORDER BY rowid DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []map[string]any{}
	for rows.Next() {
		var eventID, action, actor, outcome, at string
		if err = rows.Scan(&eventID, &action, &actor, &outcome, &at); err != nil {
			return nil, err
		}
		events = append(events, map[string]any{"id": eventID, "action": action, "actor": actor, "outcome": outcome, "time": at, "trigger": "manual"})
	}
	return map[string]any{"history": events, "total": total, "retained_count": retained, "limit": limit, "offset": in.Offset, "retention_days": 365, "record_limit": 100000, "history_limited": total > len(events), "scope": "保留最近 365 天、最多 100000 条操作摘要，支持时间与关键词筛选分页；不保存密码、令牌、正文或命令错误内容"}, rows.Err()
}

func (a *Server) dailyReportOperation(ctx context.Context, action string, in AppModuleInput) (any, error) {
	if action == "run" {
		return a.appDailyReport(ctx)
	}
	if action == "report" {
		day, err := time.Parse("2006-01-02", in.ResourceID)
		if err != nil || day.Format("2006-01-02") != in.ResourceID {
			return nil, errors.New("请选择有效的报告日期 YYYY-MM-DD")
		}
		var raw string
		if err = a.Store.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, in.ResourceID).Scan(&raw); err != nil {
			return nil, errors.New("该日期没有已保存的日报")
		}
		var report any
		if err = json.Unmarshal([]byte(raw), &report); err != nil {
			return nil, errors.New("日报记录损坏，未修改记录")
		}
		return report, nil
	}
	if action != "archive" {
		return nil, errors.New("日报操作无效")
	}
	rows, err := a.Store.DB.Query(`SELECT day,created_at,length(report) FROM app_daily_reports ORDER BY day DESC LIMIT 90`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reports := []map[string]any{}
	for rows.Next() {
		var day, at string
		var bytes int64
		if err = rows.Scan(&day, &at, &bytes); err != nil {
			return nil, err
		}
		reports = append(reports, map[string]any{"day": day, "resource_id": day, "created_at": at, "bytes": bytes})
	}
	return map[string]any{"reports": reports, "scope": "显示最近 90 个已保存日期，选择日期查看真实历史日报；不删除更早记录"}, rows.Err()
}
