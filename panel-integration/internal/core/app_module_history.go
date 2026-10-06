package core

import (
	"context"
	"encoding/json"
	"errors"
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
	if _, err = tx.Exec(`DELETE FROM app_module_events WHERE module_id=? AND rowid NOT IN (SELECT rowid FROM app_module_events WHERE module_id=? ORDER BY rowid DESC LIMIT 100)`, id, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) appModuleHistory(id string) (any, error) {
	rows, err := s.DB.Query(`SELECT id,action,actor,outcome,created_at FROM app_module_events WHERE module_id=? ORDER BY rowid DESC LIMIT 100`, id)
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
	return map[string]any{"history": events, "history_limited": true, "scope": "最近 100 条执行摘要，不保存密码、令牌、正文或命令错误内容"}, rows.Err()
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
