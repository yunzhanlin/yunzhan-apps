package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

type siteScheduleCleanup struct {
	ScheduleID, ScheduleName string
	Backup                   SiteBackup
}

func scanSiteScheduleCleanup(row interface{ Scan(...any) error }) (siteScheduleCleanup, error) {
	var v siteScheduleCleanup
	e := row.Scan(&v.ScheduleID, &v.ScheduleName, &v.Backup.ID, &v.Backup.SiteID, &v.Backup.Bytes, &v.Backup.SHA256)
	return v, e
}

func (s *Store) claimSiteScheduleCleanup() (siteScheduleCleanup, error) {
	v, e := scanSiteScheduleCleanup(s.DB.QueryRow(`SELECT schedule_id,schedule_name,artifact_id,site_id,bytes,sha256 FROM site_schedule_cleanup_jobs WHERE state='pending' ORDER BY created_at,artifact_id LIMIT 1`))
	if e == nil || !errors.Is(e, sql.ErrNoRows) {
		return v, e
	}
	v, e = scanSiteScheduleCleanup(s.DB.QueryRow(`WITH ranked AS (
 SELECT sa.schedule_id,s.name,sa.artifact_id,b.site_id,b.bytes,b.sha256,ROW_NUMBER() OVER(PARTITION BY sa.schedule_id ORDER BY sa.created_at DESC,sa.artifact_id DESC) position,s.retention_count
 FROM schedule_artifacts sa JOIN schedules s ON s.id=sa.schedule_id JOIN site_backups b ON b.id=sa.artifact_id WHERE sa.kind='site_backup'
) SELECT schedule_id,name,artifact_id,site_id,bytes,sha256 FROM ranked WHERE position>retention_count ORDER BY schedule_id,position DESC LIMIT 1`))
	if e != nil {
		return v, e
	}
	_, e = s.DB.Exec(`INSERT OR IGNORE INTO site_schedule_cleanup_jobs(artifact_id,schedule_id,schedule_name,site_id,bytes,sha256,state,created_at) VALUES(?,?,?,?,?,?,'pending',?)`, v.Backup.ID, v.ScheduleID, v.ScheduleName, v.Backup.SiteID, v.Backup.Bytes, v.Backup.SHA256, Now())
	if e != nil {
		return v, e
	}
	return scanSiteScheduleCleanup(s.DB.QueryRow(`SELECT schedule_id,schedule_name,artifact_id,site_id,bytes,sha256 FROM site_schedule_cleanup_jobs WHERE state='pending' ORDER BY created_at,artifact_id LIMIT 1`))
}

func (s *Store) cleanupSiteScheduleRetention(ctx context.Context, ex *ExecutorClient) error {
	if ex == nil {
		return nil
	}
	v, e := s.claimSiteScheduleCleanup()
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	q := url.Values{"bytes": {strconv.FormatInt(v.Backup.Bytes, 10)}, "sha256": {v.Backup.SHA256}}
	var result struct {
		Deleted bool `json:"deleted"`
	}
	e = ex.Call(ctx, http.MethodDelete, "/v1/sites/"+v.Backup.SiteID+"/backups/"+v.Backup.ID+"?"+q.Encode(), nil, &result)
	if e != nil || !result.Deleted {
		message := "执行器未确认删除网站备份"
		if e != nil {
			message = e.Error()
		}
		if len(message) > 500 {
			message = message[:500]
		}
		_, _ = s.DB.Exec(`UPDATE site_schedule_cleanup_jobs SET attempts=attempts+1,last_error=? WHERE artifact_id=? AND state='pending'`, message, v.Backup.ID)
		return errors.New(message)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	resultDB, e := tx.Exec(`DELETE FROM schedule_artifacts WHERE schedule_id=? AND artifact_id=? AND kind='site_backup'`, v.ScheduleID, v.Backup.ID)
	if e != nil {
		return e
	}
	if n, _ := resultDB.RowsAffected(); n != 1 {
		return errors.New("网站计划产物记录已变化")
	}
	resultDB, e = tx.Exec(`DELETE FROM site_backups WHERE id=? AND site_id=? AND bytes=? AND sha256=?`, v.Backup.ID, v.Backup.SiteID, v.Backup.Bytes, v.Backup.SHA256)
	if e != nil {
		return e
	}
	if n, _ := resultDB.RowsAffected(); n != 1 {
		return errors.New("网站备份记录与清理单不一致")
	}
	_, e = tx.Exec(`UPDATE site_schedule_cleanup_jobs SET state='completed',attempts=attempts+1,last_error='',completed_at=? WHERE artifact_id=? AND state='pending'`, Now(), v.Backup.ID)
	if e == nil {
		_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.site_retention',?,'success',?)`, v.ScheduleName+":"+v.Backup.ID, Now())
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
