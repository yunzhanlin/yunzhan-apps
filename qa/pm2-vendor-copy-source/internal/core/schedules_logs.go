package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func snapshotLogCleanupRun(tx *sql.Tx, run, schedule string) error {
	_, e := tx.Exec(`INSERT INTO schedule_log_operations(run_id,site_id,retention_days,created_at) SELECT ?,target_id,retention_count,? FROM schedules WHERE id=? AND kind='log_cleanup' ON CONFLICT(run_id) DO NOTHING`, run, Now(), schedule)
	return e
}

func (s *Store) executeLogCleanupScheduleRun(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var runID, scheduleID, targetID string
	var retention, attempts int
	e := s.DB.QueryRow(`SELECT r.id,r.schedule_id,COALESCE(o.site_id,''),COALESCE(o.retention_days,0),d.attempts
FROM schedule_runs r JOIN schedules s ON s.id=r.schedule_id JOIN schedule_direct_jobs d ON d.run_id=r.id LEFT JOIN schedule_log_operations o ON o.run_id=r.id
WHERE r.state='running' AND (s.kind='log_cleanup' OR o.run_id IS NOT NULL) AND d.state='pending' AND d.next_attempt_at<=? ORDER BY r.started_at,r.rowid LIMIT 1`, now.Unix()).Scan(&runID, &scheduleID, &targetID, &retention, &attempts)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if !ValidID(targetID) || retention < 1 || retention > 100 {
		return s.failScheduleRun(runID, "旧版本日志任务缺少持久参数快照；新版不会继续执行，请先核对旧版本结果", now)
	}
	var result LogCleanupResult
	e = ex.Call(ctx, http.MethodPost, "/v1/sites/"+targetID+"/logs/cleanup", LogCleanupRequest{RequestID: runID, Attempt: attempts, SiteID: targetID, RetentionDays: retention}, &result)
	if e == nil {
		for _, name := range result.Files {
			if !ValidSiteLogArchiveName(targetID, name) {
				e = errors.New("执行器日志结果包含其它网站文件；未验收为成功")
				break
			}
		}
	}
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		message := e.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		attempts++
		if attempts >= 3 {
			tx, beginErr := s.DB.Begin()
			if beginErr != nil {
				return beginErr
			}
			defer tx.Rollback()
			_, e = tx.Exec(`UPDATE schedule_direct_jobs SET attempts=?,last_error=?,state='failed' WHERE run_id=? AND state='pending'`, attempts, message, runID)
			if e == nil {
				_, e = tx.Exec(`UPDATE schedule_runs SET state='failed',finished_at=?,error=?,log=? WHERE id=? AND state='running'`, now.Unix(), message, message, runID)
			}
			if e == nil {
				e = tx.Commit()
			}
			return e
		}
		_, persistErr := s.DB.Exec(`UPDATE schedule_direct_jobs SET attempts=?,last_error=?,next_attempt_at=? WHERE run_id=? AND state='pending'`, attempts, message, now.Add(time.Duration(attempts)*2*time.Second).Unix(), runID)
		if persistErr != nil {
			return persistErr
		}
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	message := fmt.Sprintf("日志轮转 %d 个，删除 %d 个过期文件，释放 %d 字节", result.Rotated, result.Deleted, result.DeletedBytes)
	_, e = tx.Exec(`UPDATE schedule_runs SET state='succeeded',finished_at=?,log=? WHERE id=? AND state='running'`, now.Unix(), message, runID)
	if e == nil {
		_, e = tx.Exec(`UPDATE schedule_direct_jobs SET state='completed',last_error='' WHERE run_id=? AND state='pending'`, runID)
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedules SET last_run_at=? WHERE id=?`, now.Unix(), scheduleID)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
