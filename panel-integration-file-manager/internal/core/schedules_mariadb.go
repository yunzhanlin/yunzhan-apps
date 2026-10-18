package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Store) MariaDBScheduleBackup(id string) (MariaDBBackup, error) {
	var v MariaDBBackup
	var releaseID string
	e := s.DB.QueryRow(`SELECT id,database_id,instance_id,database_name,release_id,bytes,sha256,created_at FROM mariadb_schedule_backups WHERE id=?`, id).Scan(&v.ID, &v.DatabaseID, &v.InstanceID, &v.DatabaseName, &releaseID, &v.Bytes, &v.SHA256, &v.CreatedAt)
	v.Version = strings.TrimPrefix(releaseID, "mariadb-")
	return v, e
}

func (s *Store) executeMariaDBScheduleRun(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var runID, scheduleID, databaseID, instanceID, databaseName, instanceName, releaseID, artifactID string
	var attempts int
	e := s.DB.QueryRow(`SELECT r.id,r.schedule_id,t.database_id,t.instance_id,t.database_name,t.instance_name,t.release_id,r.artifact_id,d.attempts
FROM schedule_runs r JOIN schedules sc ON sc.id=r.schedule_id JOIN schedule_mariadb_targets t ON t.schedule_id=sc.id JOIN schedule_direct_jobs d ON d.run_id=r.id
WHERE r.state='running' AND sc.kind='database_backup' AND d.state='pending' AND d.next_attempt_at<=?
ORDER BY r.started_at,r.rowid LIMIT 1`, now.Unix()).Scan(&runID, &scheduleID, &databaseID, &instanceID, &databaseName, &instanceName, &releaseID, &artifactID, &attempts)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	var databases struct {
		Databases []MariaDBDatabase `json:"databases"`
	}
	var instances struct {
		Instances []MariaDBInstance `json:"instances"`
	}
	if e = ex.Call(ctx, http.MethodGet, "/v1/mariadb/databases", nil, &databases); e == nil {
		e = ex.Call(ctx, http.MethodGet, "/v1/mariadb/instances", nil, &instances)
	}
	validDB, validInstance := false, false
	for _, v := range databases.Databases {
		if v.ID == databaseID && v.InstanceID == instanceID && v.Name == databaseName {
			validDB = true
			break
		}
	}
	for _, v := range instances.Instances {
		if v.ID == instanceID && v.Name == instanceName && v.ReleaseID == releaseID && v.Status == "running" {
			validInstance = true
			break
		}
	}
	if e == nil && (!validDB || !validInstance) {
		e = errors.New("MariaDB 计划目标身份、精确版本或运行状态已变化")
	}
	var backup MariaDBBackup
	if e == nil {
		e = ex.Call(ctx, http.MethodPost, "/v1/mariadb/databases/"+databaseID+"/backup", map[string]string{"id": artifactID}, &backup)
	}
	if e != nil {
		message := e.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		attempts++
		if attempts >= 3 {
			tx, er := s.DB.Begin()
			if er != nil {
				return er
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
		_, _ = s.DB.Exec(`UPDATE schedule_runs SET log=? WHERE id=? AND state='running'`, "MariaDB 备份暂未完成，正在按同一备份身份重试："+message, runID)
		return e
	}
	if backup.ID != artifactID || backup.DatabaseID != databaseID || backup.InstanceID != instanceID || backup.DatabaseName != databaseName || backup.Version != releaseID[len("mariadb-"):] || backup.Bytes < 1 || len(backup.SHA256) != 64 {
		return s.failScheduleRun(runID, "执行器返回的 MariaDB 备份身份或摘要无效", now)
	}
	raw, _ := json.Marshal(backup)
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`INSERT INTO mariadb_schedule_backups(id,database_id,instance_id,database_name,instance_name,release_id,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, backup.ID, backup.DatabaseID, backup.InstanceID, backup.DatabaseName, instanceName, releaseID, backup.Bytes, backup.SHA256, backup.CreatedAt)
	if e == nil {
		_, e = tx.Exec(`INSERT OR IGNORE INTO schedule_artifacts(schedule_id,run_id,kind,artifact_id,created_at) VALUES(?,?,'mariadb_backup',?,?)`, scheduleID, runID, backup.ID, now.Unix())
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedule_runs SET state='succeeded',finished_at=?,log=? WHERE id=? AND state='running'`, now.Unix(), "MariaDB SQL 备份、大小与 SHA-256 已核对："+string(raw[:min(len(raw), 240)]), runID)
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
	_ = s.queueScheduleRemote(scheduleID, "mariadb", backup.ID)
	return nil
}

type mariaDBScheduleCleanup struct {
	ScheduleID, ScheduleName string
	Backup                   MariaDBBackup
}

func (s *Store) claimMariaDBScheduleCleanup() (mariaDBScheduleCleanup, error) {
	var v mariaDBScheduleCleanup
	scan := func(row *sql.Row) error {
		return row.Scan(&v.ScheduleID, &v.ScheduleName, &v.Backup.ID, &v.Backup.DatabaseID, &v.Backup.InstanceID, &v.Backup.DatabaseName, &v.Backup.Version, &v.Backup.Bytes, &v.Backup.SHA256, &v.Backup.CreatedAt)
	}
	e := scan(s.DB.QueryRow(`SELECT schedule_id,schedule_name,artifact_id,database_id,instance_id,'', '',bytes,sha256,created_at FROM mariadb_schedule_cleanup_jobs WHERE state='pending' ORDER BY created_at,artifact_id LIMIT 1`))
	if e == nil || !errors.Is(e, sql.ErrNoRows) {
		return v, e
	}
	e = scan(s.DB.QueryRow(`WITH ranked AS (
SELECT sa.schedule_id,s.name,sa.artifact_id,b.database_id,b.instance_id,b.database_name,b.release_id,b.bytes,b.sha256,b.created_at,
ROW_NUMBER() OVER(PARTITION BY sa.schedule_id ORDER BY sa.created_at DESC,sa.artifact_id DESC) position,s.retention_count
FROM schedule_artifacts sa JOIN schedules s ON s.id=sa.schedule_id JOIN mariadb_schedule_backups b ON b.id=sa.artifact_id
WHERE sa.kind='mariadb_backup')
SELECT schedule_id,name,artifact_id,database_id,instance_id,database_name,release_id,bytes,sha256,created_at
FROM ranked WHERE position>retention_count
AND NOT EXISTS (SELECT 1 FROM mariadb_remote_copies rc WHERE rc.artifact_id=ranked.artifact_id AND rc.state!='succeeded')
ORDER BY schedule_id,position DESC LIMIT 1`))
	if e != nil {
		return v, e
	}
	_, e = s.DB.Exec(`INSERT OR IGNORE INTO mariadb_schedule_cleanup_jobs(artifact_id,schedule_id,schedule_name,database_id,instance_id,bytes,sha256,state,created_at) VALUES(?,?,?,?,?,?,?,'pending',?)`, v.Backup.ID, v.ScheduleID, v.ScheduleName, v.Backup.DatabaseID, v.Backup.InstanceID, v.Backup.Bytes, v.Backup.SHA256, Now())
	return v, e
}
func (s *Store) cleanupMariaDBScheduleRetention(ctx context.Context, ex *ExecutorClient) error {
	if ex == nil {
		return nil
	}
	v, e := s.claimMariaDBScheduleCleanup()
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	q := url.Values{"database_id": {v.Backup.DatabaseID}, "instance_id": {v.Backup.InstanceID}, "bytes": {strconv.FormatInt(v.Backup.Bytes, 10)}, "sha256": {v.Backup.SHA256}}
	var result struct {
		Deleted bool `json:"deleted"`
	}
	e = ex.Call(ctx, http.MethodDelete, "/v1/mariadb/backups/"+v.Backup.ID+"/scheduled?"+q.Encode(), nil, &result)
	if e != nil || !result.Deleted {
		message := "执行器未确认删除 MariaDB 计划备份"
		if e != nil {
			message = e.Error()
		}
		if len(message) > 500 {
			message = message[:500]
		}
		_, _ = s.DB.Exec(`UPDATE mariadb_schedule_cleanup_jobs SET attempts=attempts+1,last_error=? WHERE artifact_id=? AND state='pending'`, message, v.Backup.ID)
		return errors.New(message)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec(`DELETE FROM schedule_artifacts WHERE schedule_id=? AND artifact_id=? AND kind='mariadb_backup'`, v.ScheduleID, v.Backup.ID)
	if e != nil {
		return e
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("MariaDB 计划产物记录已变化")
	}
	res, e = tx.Exec(`DELETE FROM mariadb_schedule_backups WHERE id=? AND database_id=? AND instance_id=? AND bytes=? AND sha256=?`, v.Backup.ID, v.Backup.DatabaseID, v.Backup.InstanceID, v.Backup.Bytes, v.Backup.SHA256)
	if e != nil {
		return e
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("MariaDB 备份镜像与清理单不一致")
	}
	_, e = tx.Exec(`UPDATE mariadb_schedule_cleanup_jobs SET state='completed',attempts=attempts+1,last_error='',completed_at=? WHERE artifact_id=? AND state='pending'`, Now(), v.Backup.ID)
	if e == nil {
		_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.mariadb_retention',?,'success',?)`, v.ScheduleName+":"+v.Backup.ID, Now())
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
