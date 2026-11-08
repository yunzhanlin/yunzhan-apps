package core

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (s *Store) recordAppModuleEvent(id, action, actor string, operationError error) error {
	return s.recordAppModuleEventContext(context.Background(), id, action, actor, operationError)
}

func (s *Store) recordAppModuleEventContext(ctx context.Context, id, action, actor string, operationError error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = recordAppModuleEventTx(ctx, tx, id, action, actor, operationError); err != nil {
		return err
	}
	return tx.Commit()
}

// The caller owns the transaction: account changes, session invalidation,
// success history and its audit must either all commit or all roll back.
func recordAppModuleEventTx(ctx context.Context, tx *sql.Tx, id, action, actor string, operationError error) error {
	outcome := "succeeded"
	if operationError != nil {
		outcome = "failed"
	}
	// Never persist operation inputs, output tokens or command errors here.
	if _, err := tx.ExecContext(ctx, `INSERT INTO app_module_events(id,module_id,action,actor,outcome,created_at) VALUES(?,?,?,?,?,?)`, ID(), id, action, actor, outcome, Now()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_module_events WHERE module_id=? AND created_at<?`, id, time.Now().AddDate(0, 0, -365).UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_module_events WHERE module_id=? AND rowid <= COALESCE((SELECT rowid FROM app_module_events WHERE module_id=? ORDER BY rowid DESC LIMIT 1 OFFSET 100000),-1)`, id, id); err != nil {
		return err
	}
	return nil
}

func recordAppUserOutcomeTx(ctx context.Context, tx *sql.Tx, actor, action string, operationError error) error {
	return recordCoreModuleOutcomeTx(ctx, tx, "user-manager", actor, action, operationError)
}

func recordCoreModuleOutcomeTx(ctx context.Context, tx *sql.Tx, module, actor, action string, operationError error) error {
	if module != "user-manager" && module != "platform-ops" {
		return errors.New("不是本地事务管理模块")
	}
	if err := recordAppModuleEventTx(ctx, tx, module, action, actor, operationError); err != nil {
		return err
	}
	result := "succeeded"
	if operationError != nil {
		result = "failed"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, actor, "app-module."+action, module, result, Now())
	return err
}

func (s *Store) recordAppUserFailure(ctx context.Context, actor, action string, operationError error) error {
	return s.recordCoreModuleFailure(ctx, "user-manager", actor, action, operationError)
}

func (s *Store) recordCoreModuleFailure(ctx context.Context, module, actor, action string, operationError error) error {
	if operationError == nil {
		return errors.New("不能将成功的本地模块操作记录为失败")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = recordCoreModuleOutcomeTx(ctx, tx, module, actor, action, operationError); err != nil {
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
		_, report, err := readDailyReportRecord(ctx, a.Store.DB, in.ResourceID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("该日期没有已保存的日报")
		}
		if err != nil {
			return nil, err
		}
		return report, nil
	}
	if action != "archive" {
		return nil, errors.New("日报操作无效")
	}
	if in.Limit < 0 || in.Limit > 100 || in.Offset < 0 || in.Offset > 100000 {
		return nil, errors.New("日报目录分页无效；每页最多 100 条，起点最多 100000")
	}
	limit := in.Limit
	if limit == 0 {
		limit = 90
	}
	var total int
	if err := a.Store.DB.QueryRowContext(ctx, `SELECT count(*) FROM app_daily_reports`).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := a.Store.DB.QueryContext(ctx, `SELECT day,created_at,length(CAST(report AS BLOB)) FROM app_daily_reports ORDER BY day DESC LIMIT ? OFFSET ?`, limit, in.Offset)
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
		if !validDailyReportDay(day) {
			return nil, errors.New("日报目录含无效日期身份，未返回部分正常库存")
		}
		if _, err := time.Parse(time.RFC3339, at); err != nil {
			return nil, errors.New("日报目录含无效生成时间，保留原记录")
		}
		reports = append(reports, map[string]any{"day": day, "resource_id": day, "created_at": at, "bytes": bytes, "record_size_valid": bytes > 0 && bytes <= dailyReportRecordBytes})
	}
	return map[string]any{"reports": reports, "total": total, "limit": limit, "offset": in.Offset, "read_only": true, "report_contents_verified": false, "scope": "只读分页实际保存日期，默认每页 90 条、最多 100 条；字节数不等于内容已校验，选择日期后才严格核对原报告。不删除、修复或重写更早记录。"}, rows.Err()
}
