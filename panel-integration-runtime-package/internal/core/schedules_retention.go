package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

type scheduleCleanup struct {
	ScheduleID   string
	ScheduleName string
	Backup       DatabaseBackup
	State        string
}

func scanScheduleCleanup(row interface{ Scan(...any) error }) (scheduleCleanup, error) {
	var v scheduleCleanup
	e := row.Scan(&v.ScheduleID, &v.ScheduleName, &v.Backup.ID, &v.Backup.DatabaseID, &v.Backup.ServerID, &v.Backup.Version, &v.Backup.Bytes, &v.Backup.SHA256, &v.State)
	return v, e
}

func (s *Store) pendingScheduleCleanup() (scheduleCleanup, error) {
	return scanScheduleCleanup(s.DB.QueryRow(`SELECT schedule_id,schedule_name,artifact_id,database_id,server_id,version,bytes,sha256,state
FROM schedule_cleanup_jobs WHERE state='pending' ORDER BY created_at,artifact_id LIMIT 1`))
}

func (s *Store) claimScheduleCleanup() (scheduleCleanup, error) {
	if v, e := s.pendingScheduleCleanup(); e == nil || !errors.Is(e, sql.ErrNoRows) {
		return v, e
	}
	row := s.DB.QueryRow(`WITH ranked AS (
 SELECT sa.schedule_id,s.name AS schedule_name,sa.artifact_id,b.database_id,b.server_id,b.version,b.bytes,b.sha256,
        ROW_NUMBER() OVER(PARTITION BY sa.schedule_id ORDER BY sa.created_at DESC,sa.artifact_id DESC) AS position,
        s.retention_count
 FROM schedule_artifacts sa JOIN schedules s ON s.id=sa.schedule_id JOIN mysql_backups b ON b.id=sa.artifact_id
 WHERE sa.kind='database_backup'
)
SELECT schedule_id,schedule_name,artifact_id,database_id,server_id,version,bytes,sha256,'pending'
FROM ranked WHERE position>retention_count ORDER BY schedule_id,position DESC LIMIT 1`)
	v, e := scanScheduleCleanup(row)
	if e != nil {
		return v, e
	}
	_, e = s.DB.Exec(`INSERT OR IGNORE INTO schedule_cleanup_jobs(artifact_id,schedule_id,schedule_name,database_id,server_id,version,bytes,sha256,state,created_at) VALUES(?,?,?,?,?,?,?,?,'pending',?)`,
		v.Backup.ID, v.ScheduleID, v.ScheduleName, v.Backup.DatabaseID, v.Backup.ServerID, v.Backup.Version, v.Backup.Bytes, v.Backup.SHA256, Now())
	if e != nil {
		return v, e
	}
	return s.pendingScheduleCleanup()
}

func (s *Store) cleanupScheduleRetention(ctx context.Context, ex *ExecutorClient) error {
	if ex == nil {
		return nil
	}
	v, e := s.claimScheduleCleanup()
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	q := url.Values{
		"database_id": {v.Backup.DatabaseID},
		"sha256":      {v.Backup.SHA256},
		"bytes":       {strconv.FormatInt(v.Backup.Bytes, 10)},
		"version":     {v.Backup.Version},
	}
	var out struct {
		Deleted bool `json:"deleted"`
	}
	path := "/v1/databases/backups/" + v.Backup.ServerID + "/" + v.Backup.ID + "?" + q.Encode()
	if e = ex.Call(ctx, http.MethodDelete, path, nil, &out); e != nil || !out.Deleted {
		message := "执行器未确认删除"
		if e != nil {
			message = e.Error()
		}
		if len(message) > 500 {
			message = message[:500]
		}
		_, _ = s.DB.Exec(`UPDATE schedule_cleanup_jobs SET attempts=attempts+1,last_error=? WHERE artifact_id=? AND state='pending'`, message, v.Backup.ID)
		return errors.New(message)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.Exec(`DELETE FROM schedule_artifacts WHERE schedule_id=? AND artifact_id=? AND kind='database_backup'`, v.ScheduleID, v.Backup.ID)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("计划备份产物记录已变化")
	}
	result, e = tx.Exec(`DELETE FROM mysql_backups WHERE id=? AND database_id=? AND server_id=? AND version=? AND bytes=? AND sha256=?`, v.Backup.ID, v.Backup.DatabaseID, v.Backup.ServerID, v.Backup.Version, v.Backup.Bytes, v.Backup.SHA256)
	if e != nil {
		return e
	}
	n, _ = result.RowsAffected()
	if n != 1 {
		return errors.New("数据库备份记录与清理单不一致")
	}
	_, e = tx.Exec(`UPDATE schedule_cleanup_jobs SET state='completed',attempts=attempts+1,last_error='',completed_at=? WHERE artifact_id=? AND state='pending'`, Now(), v.Backup.ID)
	if e == nil {
		_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.retention',?,'success',?)`, v.ScheduleName+":"+v.Backup.ID, Now())
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
