package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func (s *Store) executeLogCleanupScheduleRun(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var runID, scheduleID, targetID string
	var retention, attempts int
	e := s.DB.QueryRow(`SELECT r.id,r.schedule_id,s.target_id,s.retention_count,d.attempts
FROM schedule_runs r JOIN schedules s ON s.id=r.schedule_id JOIN schedule_direct_jobs d ON d.run_id=r.id
WHERE r.state='running' AND s.kind='log_cleanup' AND d.state='pending' AND d.next_attempt_at<=? ORDER BY r.started_at,r.rowid LIMIT 1`, now.Unix()).Scan(&runID, &scheduleID, &targetID, &retention, &attempts)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	var result LogCleanupResult
	e = ex.Call(ctx, http.MethodPost, "/v1/sites/"+targetID+"/logs/cleanup", LogCleanupRequest{SiteID: targetID, RetentionDays: retention}, &result)
	if e != nil {
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
		_, _ = s.DB.Exec(`UPDATE schedule_direct_jobs SET attempts=?,last_error=?,next_attempt_at=? WHERE run_id=? AND state='pending'`, attempts, message, now.Add(time.Duration(attempts)*2*time.Second).Unix(), runID)
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
