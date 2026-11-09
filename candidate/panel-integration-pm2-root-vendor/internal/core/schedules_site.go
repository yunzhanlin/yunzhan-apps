package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (s *Store) executeSiteScheduleRun(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var runID, scheduleID, targetID, artifactID string
	var attempts int
	e := s.DB.QueryRow(`SELECT r.id,r.schedule_id,s.target_id,r.artifact_id,d.attempts
FROM schedule_runs r JOIN schedules s ON s.id=r.schedule_id JOIN schedule_direct_jobs d ON d.run_id=r.id
WHERE r.state='running' AND s.kind='site_backup' AND d.state='pending' AND d.next_attempt_at<=?
ORDER BY r.started_at,r.rowid LIMIT 1`, now.Unix()).Scan(&runID, &scheduleID, &targetID, &artifactID, &attempts)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	request := SiteBackup{ID: artifactID, SiteID: targetID}
	var backup SiteBackup
	e = ex.Call(ctx, http.MethodPost, "/v1/sites/"+targetID+"/backups", request, &backup)
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
		_, _ = s.DB.Exec(`UPDATE schedule_runs SET log=? WHERE id=? AND state='running'`, "网站归档暂未完成，正在按同一备份身份重试："+message, runID)
		return e
	}
	if backup.ID != artifactID || backup.SiteID != targetID || backup.Format != "zip" || backup.Bytes < 0 || backup.Files < 0 || len(backup.SHA256) != 64 {
		return s.failScheduleRun(runID, "执行器返回的网站备份身份或摘要无效", now)
	}
	raw, _ := json.Marshal(backup)
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`INSERT INTO site_backups(id,site_id,format,files,source_bytes,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, backup.ID, backup.SiteID, backup.Format, backup.Files, backup.SourceBytes, backup.Bytes, backup.SHA256, backup.CreatedAt)
	if e == nil {
		_, e = tx.Exec(`INSERT OR IGNORE INTO schedule_artifacts(schedule_id,run_id,kind,artifact_id,created_at) VALUES(?,?,'site_backup',?,?)`, scheduleID, runID, backup.ID, now.Unix())
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedule_runs SET state='succeeded',finished_at=?,log=? WHERE id=? AND state='running'`, now.Unix(), "网站公开文件归档完成，清单、大小与 SHA-256 已核对："+string(raw[:min(len(raw), 240)]), runID)
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedule_direct_jobs SET state='completed',last_error='' WHERE run_id=? AND state='pending'`, runID)
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedules SET last_run_at=? WHERE id=?`, now.Unix(), scheduleID)
	}
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	_ = s.queueScheduleRemote(scheduleID, "site", backup.ID)
	return nil
}
