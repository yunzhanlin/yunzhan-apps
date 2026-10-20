package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Schedule struct {
	Script         string `json:"script,omitempty"`
	ScriptSiteID   string `json:"script_site_id,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	RemoteID       string `json:"remote_id,omitempty"`
	RemoteName     string `json:"remote_name,omitempty"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	TargetID       string `json:"target_id"`
	TargetName     string `json:"target_name"`
	DatabaseEngine string `json:"database_engine,omitempty"`
	InstanceID     string `json:"instance_id,omitempty"`
	InstanceName   string `json:"instance_name,omitempty"`
	ReleaseID      string `json:"release_id,omitempty"`
	ScheduleType   string `json:"schedule_type"`
	Timezone       string `json:"timezone"`
	Minute         int    `json:"minute"`
	Hour           int    `json:"hour"`
	Weekday        int    `json:"weekday"`
	RetentionCount int    `json:"retention_count"`
	Enabled        bool   `json:"enabled"`
	Revision       int64  `json:"revision"`
	NextRunAt      int64  `json:"next_run_at"`
	LastRunAt      int64  `json:"last_run_at,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type ScheduleRun struct {
	ID           string `json:"id"`
	ScheduleID   string `json:"schedule_id"`
	ScheduleName string `json:"schedule_name"`
	Trigger      string `json:"trigger"`
	State        string `json:"state"`
	ScheduledFor int64  `json:"scheduled_for"`
	StartedAt    int64  `json:"started_at,omitempty"`
	FinishedAt   int64  `json:"finished_at,omitempty"`
	JobID        string `json:"job_id,omitempty"`
	ArtifactID   string `json:"artifact_id,omitempty"`
	Error        string `json:"error,omitempty"`
	Log          string `json:"log,omitempty"`
	CreatedAt    string `json:"created_at"`
	LogCleanup   bool   `json:"log_cleanup"`
}

func (s *Store) migrateSchedules() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schedules(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('database_backup','site_backup','log_cleanup','admin_script')),target_id TEXT NOT NULL,
 schedule_type TEXT NOT NULL CHECK(schedule_type IN ('hourly','daily','weekly')),timezone TEXT NOT NULL,minute INTEGER NOT NULL CHECK(minute BETWEEN 0 AND 59),hour INTEGER NOT NULL CHECK(hour BETWEEN 0 AND 23),weekday INTEGER NOT NULL CHECK(weekday BETWEEN 0 AND 6),
 retention_count INTEGER NOT NULL CHECK(retention_count BETWEEN 1 AND 100),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),revision INTEGER NOT NULL CHECK(revision>0),next_run_at INTEGER NOT NULL,last_run_at INTEGER NOT NULL DEFAULT 0,deleted_at INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS active_schedule_name ON schedules(name) WHERE deleted_at=0;
 CREATE INDEX IF NOT EXISTS schedules_due ON schedules(enabled,next_run_at) WHERE deleted_at=0;
 CREATE TABLE IF NOT EXISTS schedule_runs(
 id TEXT PRIMARY KEY,schedule_id TEXT NOT NULL REFERENCES schedules(id),schedule_name TEXT NOT NULL,trigger TEXT NOT NULL CHECK(trigger IN ('scheduled','manual')),state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','skipped')),scheduled_for INTEGER NOT NULL,started_at INTEGER NOT NULL DEFAULT 0,finished_at INTEGER NOT NULL DEFAULT 0,job_id TEXT NOT NULL DEFAULT '',artifact_id TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',log TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS one_active_schedule_run ON schedule_runs(schedule_id) WHERE state IN ('queued','running');
 CREATE INDEX IF NOT EXISTS schedule_runs_recent ON schedule_runs(scheduled_for DESC);
 CREATE TABLE IF NOT EXISTS schedule_artifacts(schedule_id TEXT NOT NULL REFERENCES schedules(id),run_id TEXT NOT NULL UNIQUE REFERENCES schedule_runs(id),kind TEXT NOT NULL,artifact_id TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,PRIMARY KEY(schedule_id,artifact_id));
 CREATE TABLE IF NOT EXISTS schedule_cleanup_jobs(
 artifact_id TEXT PRIMARY KEY,schedule_id TEXT NOT NULL REFERENCES schedules(id),schedule_name TEXT NOT NULL,database_id TEXT NOT NULL,server_id TEXT NOT NULL,version TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','completed')),attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,completed_at TEXT NOT NULL DEFAULT '');
 CREATE INDEX IF NOT EXISTS schedule_cleanup_pending ON schedule_cleanup_jobs(state,created_at);
 CREATE TABLE IF NOT EXISTS site_backups(id TEXT PRIMARY KEY,site_id TEXT NOT NULL REFERENCES sites(id),format TEXT NOT NULL,files INTEGER NOT NULL,source_bytes INTEGER NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS schedule_direct_jobs(run_id TEXT PRIMARY KEY REFERENCES schedule_runs(id),attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',state TEXT NOT NULL CHECK(state IN ('pending','completed','failed')));
 CREATE TABLE IF NOT EXISTS schedule_log_operations(run_id TEXT PRIMARY KEY REFERENCES schedule_runs(id),site_id TEXT NOT NULL REFERENCES sites(id),retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 100),created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS site_schedule_cleanup_jobs(artifact_id TEXT PRIMARY KEY,schedule_id TEXT NOT NULL REFERENCES schedules(id),schedule_name TEXT NOT NULL,site_id TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','completed')),attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,completed_at TEXT NOT NULL DEFAULT '');
 CREATE INDEX IF NOT EXISTS site_schedule_cleanup_pending ON site_schedule_cleanup_jobs(state,created_at);
	CREATE TABLE IF NOT EXISTS schedule_scripts(schedule_id TEXT PRIMARY KEY REFERENCES schedules(id),script TEXT NOT NULL,timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 60));
	CREATE TABLE IF NOT EXISTS schedule_run_scripts(run_id TEXT PRIMARY KEY REFERENCES schedule_runs(id),script TEXT NOT NULL,timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 60),script_sha256 TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS schedule_php_scripts(schedule_id TEXT PRIMARY KEY REFERENCES schedules(id),site_id TEXT NOT NULL REFERENCES sites(id));
	CREATE TABLE IF NOT EXISTS schedule_run_php_scripts(run_id TEXT PRIMARY KEY REFERENCES schedule_runs(id),site_id TEXT NOT NULL REFERENCES sites(id),php_version_id TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS schedule_mariadb_targets(
	 schedule_id TEXT PRIMARY KEY REFERENCES schedules(id),database_id TEXT NOT NULL,instance_id TEXT NOT NULL,database_name TEXT NOT NULL,instance_name TEXT NOT NULL,release_id TEXT NOT NULL);
	CREATE UNIQUE INDEX IF NOT EXISTS one_mariadb_target_per_schedule ON schedule_mariadb_targets(schedule_id,database_id,instance_id);
	CREATE TABLE IF NOT EXISTS mariadb_schedule_backups(
	 id TEXT PRIMARY KEY,database_id TEXT NOT NULL,instance_id TEXT NOT NULL,database_name TEXT NOT NULL,instance_name TEXT NOT NULL,release_id TEXT NOT NULL,bytes INTEGER NOT NULL CHECK(bytes>0),sha256 TEXT NOT NULL,created_at TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS mariadb_schedule_cleanup_jobs(
	 artifact_id TEXT PRIMARY KEY,schedule_id TEXT NOT NULL REFERENCES schedules(id),schedule_name TEXT NOT NULL,database_id TEXT NOT NULL,instance_id TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,
	 state TEXT NOT NULL CHECK(state IN ('pending','completed')),attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,completed_at TEXT NOT NULL DEFAULT '');
	CREATE INDEX IF NOT EXISTS mariadb_schedule_cleanup_pending ON mariadb_schedule_cleanup_jobs(state,created_at);
	INSERT OR IGNORE INTO schema_migrations VALUES(15,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
	INSERT OR IGNORE INTO schema_migrations VALUES(16,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
	INSERT OR IGNORE INTO schema_migrations VALUES(23,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
	INSERT OR IGNORE INTO schema_migrations VALUES(38,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func validSchedule(v Schedule) error {
	v.Name = strings.TrimSpace(v.Name)
	if len([]rune(v.Name)) < 1 || len([]rune(v.Name)) > 60 {
		return errors.New("计划名称应为 1–60 个字符")
	}
	if v.Kind != "database_backup" && v.Kind != "site_backup" && v.Kind != "log_cleanup" && v.Kind != "admin_script" {
		return errors.New("计划任务类型无效")
	}
	if !ValidID(v.TargetID) || (v.ScheduleType != "hourly" && v.ScheduleType != "daily" && v.ScheduleType != "weekly") || v.Minute < 0 || v.Minute > 59 || v.Hour < 0 || v.Hour > 23 || v.Weekday < 0 || v.Weekday > 6 || v.RetentionCount < 1 || v.RetentionCount > 100 {
		return errors.New("计划参数无效")
	}
	if _, e := time.LoadLocation(v.Timezone); e != nil {
		return errors.New("时区无效")
	}
	return nil
}

func validScheduleScript(v Schedule) error {
	if v.Kind != "admin_script" {
		if v.ScriptSiteID != "" {
			return errors.New("只有脚本任务可以绑定网站 PHP")
		}
		return nil
	}
	if len(v.Script) < 1 || len(v.Script) > 16*1024 || strings.ContainsRune(v.Script, 0) || v.TimeoutSeconds < 1 || v.TimeoutSeconds > 60 {
		return errors.New("脚本应为 1–16384 字节，超时为 1–60 秒")
	}
	if v.ScriptSiteID != "" && (!ValidID(v.ScriptSiteID) || !ValidSitePHPScriptPath(v.Script)) {
		return errors.New("请选择网站，并填写公开目录内的相对 PHP 文件路径，例如 cron/task.php")
	}
	return nil
}

func nextScheduleTime(v Schedule, after time.Time) (time.Time, error) {
	if e := validSchedule(v); e != nil {
		return time.Time{}, e
	}
	loc, _ := time.LoadLocation(v.Timezone)
	local := after.In(loc)
	wall := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), 0, 0, 0, time.UTC)
	switch v.ScheduleType {
	case "hourly":
		for n := 0; n < 24*370; n++ {
			candidateWall := wall.Add(time.Duration(n) * time.Hour)
			candidate := resolveLocalTime(candidateWall.Year(), candidateWall.Month(), candidateWall.Day(), candidateWall.Hour(), v.Minute, loc)
			if candidate.After(after) {
				return candidate.UTC(), nil
			}
		}
	case "daily", "weekly":
		day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
		for n := 0; n < 370; n++ {
			candidateDay := day.AddDate(0, 0, n)
			candidate := resolveLocalTime(candidateDay.Year(), candidateDay.Month(), candidateDay.Day(), v.Hour, v.Minute, loc)
			if v.ScheduleType == "weekly" && int(candidate.Weekday()) != v.Weekday {
				continue
			}
			if candidate.After(after) {
				return candidate.UTC(), nil
			}
		}
	}
	return time.Time{}, errors.New("无法计算下次执行时间")
}

func resolveLocalTime(year int, month time.Month, day, hour, minute int, loc *time.Location) time.Time {
	wanted := time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
	for offset := 0; offset <= 180; offset++ {
		wall := wanted.Add(time.Duration(offset) * time.Minute)
		candidate := time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), 0, 0, loc)
		local := candidate.In(loc)
		if local.Year() == wall.Year() && local.Month() == wall.Month() && local.Day() == wall.Day() && local.Hour() == wall.Hour() && local.Minute() == wall.Minute() {
			return candidate
		}
	}
	return time.Date(year, month, day, hour, minute, 0, 0, loc)
}

func scanSchedule(row interface{ Scan(...any) error }) (Schedule, error) {
	var v Schedule
	var enabled int
	e := row.Scan(&v.ID, &v.Name, &v.Kind, &v.TargetID, &v.TargetName, &v.DatabaseEngine, &v.InstanceID, &v.InstanceName, &v.ReleaseID, &v.ScheduleType, &v.Timezone, &v.Minute, &v.Hour, &v.Weekday, &v.RetentionCount, &enabled, &v.Revision, &v.NextRunAt, &v.LastRunAt, &v.CreatedAt, &v.UpdatedAt, &v.Script, &v.TimeoutSeconds, &v.RemoteID, &v.RemoteName, &v.ScriptSiteID)
	v.Enabled = enabled == 1
	return v, e
}

const scheduleSelect = `SELECT s.id,s.name,s.kind,s.target_id,CASE WHEN sp.site_id IS NOT NULL THEN COALESCE(pw.name,'') WHEN s.kind='admin_script' THEN '受限 panel-task 用户' ELSE COALESCE(mt.database_name,d.name,w.name,'') END,CASE WHEN mt.schedule_id IS NOT NULL THEN 'mariadb' WHEN s.kind='database_backup' THEN 'mysql' ELSE '' END,COALESCE(mt.instance_id,''),COALESCE(mt.instance_name,''),CASE WHEN sp.site_id IS NOT NULL THEN COALESCE(pw.php_version_id,'') ELSE COALESCE(mt.release_id,'') END,s.schedule_type,s.timezone,s.minute,s.hour,s.weekday,s.retention_count,s.enabled,s.revision,s.next_run_at,s.last_run_at,s.created_at,s.updated_at,COALESCE(ss.script,''),COALESCE(ss.timeout_seconds,0),COALESCE(sr.remote_id,''),COALESCE(br.name,''),COALESCE(sp.site_id,'') FROM schedules s LEFT JOIN schedule_mariadb_targets mt ON mt.schedule_id=s.id LEFT JOIN mysql_databases d ON d.id=s.target_id AND s.kind='database_backup' AND mt.schedule_id IS NULL LEFT JOIN sites w ON w.id=s.target_id AND s.kind IN ('site_backup','log_cleanup') LEFT JOIN schedule_scripts ss ON ss.schedule_id=s.id LEFT JOIN schedule_php_scripts sp ON sp.schedule_id=s.id LEFT JOIN sites pw ON pw.id=sp.site_id LEFT JOIN schedule_remotes sr ON sr.schedule_id=s.id LEFT JOIN backup_remotes br ON br.id=sr.remote_id`

func (s *Store) Schedules() ([]Schedule, error) {
	rows, e := s.DB.Query(scheduleSelect + ` WHERE s.deleted_at=0 ORDER BY s.created_at DESC,s.rowid DESC`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		v, e := scanSchedule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) Schedule(id string) (Schedule, error) {
	return scanSchedule(s.DB.QueryRow(scheduleSelect+` WHERE s.id=? AND s.deleted_at=0`, id))
}

func (s *Store) validateScheduleTarget(v Schedule) error {
	if v.RemoteID != "" {
		if v.Kind != "database_backup" && v.Kind != "site_backup" {
			return errors.New("只有备份计划可以选择远端存储")
		}
		if !ValidID(v.RemoteID) {
			return errors.New("远端存储标识无效")
		}
		if _, e := s.BackupRemote(v.RemoteID); e != nil {
			return errors.New("远端存储不存在")
		}
	}
	if v.Kind == "admin_script" {
		if e := validScheduleScript(v); e != nil {
			return e
		}
		if v.ScriptSiteID != "" {
			site, e := s.Site(v.ScriptSiteID)
			if e != nil || (site.Status != "running" && site.Status != "stopped") || site.PHPVersionID == "" {
				return errors.New("目标网站未就绪或尚未绑定 PHP")
			}
		}
		return nil
	}
	if v.Kind == "site_backup" || v.Kind == "log_cleanup" {
		site, e := s.Site(v.TargetID)
		if e != nil || site.Status == "provisioning" || site.Status == "needs_attention" {
			return errors.New("目标网站不存在或尚未就绪")
		}
		return nil
	}
	if v.Kind == "database_backup" && v.DatabaseEngine == "mariadb" {
		if !ValidID(v.TargetID) || !ValidID(v.InstanceID) || !ValidDatabaseName(v.TargetName) || strings.TrimSpace(v.InstanceName) == "" || !strings.HasPrefix(v.ReleaseID, "mariadb-") {
			return errors.New("MariaDB 计划目标无效")
		}
		return nil
	}
	db, e := s.Database(v.TargetID)
	if e != nil || db.Status != "ready" {
		return errors.New("目标数据库不存在或尚未就绪")
	}
	server, e := s.DatabaseServer(db.ServerID)
	if e != nil || server.Status != "running" {
		return errors.New("目标 MySQL 实例未运行")
	}
	return nil
}

func (s *Store) CreateSchedule(v Schedule, actor string, now time.Time) (Schedule, error) {
	v.Name = strings.TrimSpace(v.Name)
	if e := validSchedule(v); e != nil {
		return v, e
	}
	if e := validScheduleScript(v); e != nil {
		return v, e
	}
	if e := s.validateScheduleTarget(v); e != nil {
		return v, e
	}
	next, e := nextScheduleTime(v, now)
	if e != nil {
		return v, e
	}
	v.ID, v.Revision, v.NextRunAt, v.CreatedAt, v.UpdatedAt = ID(), 1, next.Unix(), Now(), Now()
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`INSERT INTO schedules(id,name,kind,target_id,schedule_type,timezone,minute,hour,weekday,retention_count,enabled,revision,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.ID, v.Name, v.Kind, v.TargetID, v.ScheduleType, v.Timezone, v.Minute, v.Hour, v.Weekday, v.RetentionCount, v.Enabled, v.Revision, v.NextRunAt, v.CreatedAt, v.UpdatedAt)
	if e != nil {
		return v, errors.New("计划名称已存在")
	}
	if e = saveSchedulePHPScript(tx, v.ID, v.ScriptSiteID); e != nil {
		return v, e
	}
	if v.Kind == "admin_script" {
		if _, e = tx.Exec(`INSERT INTO schedule_scripts VALUES(?,?,?)`, v.ID, v.Script, v.TimeoutSeconds); e != nil {
			return v, e
		}
	}
	if v.RemoteID != "" {
		if _, e = tx.Exec(`INSERT INTO schedule_remotes(schedule_id,remote_id) VALUES(?,?)`, v.ID, v.RemoteID); e != nil {
			return v, e
		}
	}
	if v.Kind == "database_backup" && v.DatabaseEngine == "mariadb" {
		_, e = tx.Exec(`INSERT INTO schedule_mariadb_targets(schedule_id,database_id,instance_id,database_name,instance_name,release_id) VALUES(?,?,?,?,?,?)`, v.ID, v.TargetID, v.InstanceID, v.TargetName, v.InstanceName, v.ReleaseID)
		if e != nil {
			return v, e
		}
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'schedule.create',?,'success',?)`, actor, v.Name, Now()); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	return s.Schedule(v.ID)
}

func (s *Store) UpdateSchedule(id string, v Schedule, actor string, now time.Time) (Schedule, error) {
	if !ValidID(id) || v.Revision < 1 {
		return v, errors.New("计划修订无效")
	}
	v.Name = strings.TrimSpace(v.Name)
	if e := validSchedule(v); e != nil {
		return v, e
	}
	if e := validScheduleScript(v); e != nil {
		return v, e
	}
	if e := s.validateScheduleTarget(v); e != nil {
		return v, e
	}
	next, e := nextScheduleTime(v, now)
	if e != nil {
		return v, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	var previousKind, previousTarget string
	var previousRetention, activeRuns int
	if e = tx.QueryRow(`SELECT kind,target_id,retention_count,(SELECT count(*) FROM schedule_runs WHERE schedule_id=schedules.id AND state IN ('queued','running')) FROM schedules WHERE id=? AND deleted_at=0`, id).Scan(&previousKind, &previousTarget, &previousRetention, &activeRuns); e != nil {
		return v, e
	}
	if activeRuns > 0 && (previousKind == "log_cleanup" || v.Kind == "log_cleanup") && (previousKind != v.Kind || previousTarget != v.TargetID || previousRetention != v.RetentionCount) {
		return v, errors.New("日志计划正在排队或执行；当前操作的类型、网站和保留天数不可变，完成后再修改")
	}
	result, e := tx.Exec(`UPDATE schedules SET name=?,kind=?,target_id=?,schedule_type=?,timezone=?,minute=?,hour=?,weekday=?,retention_count=?,enabled=?,revision=revision+1,next_run_at=?,updated_at=? WHERE id=? AND revision=? AND deleted_at=0`, v.Name, v.Kind, v.TargetID, v.ScheduleType, v.Timezone, v.Minute, v.Hour, v.Weekday, v.RetentionCount, v.Enabled, next.Unix(), Now(), id, v.Revision)
	if e != nil {
		return v, errors.New("计划名称已存在")
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return v, errors.New("计划已变化，请刷新后重试")
	}
	if e = saveSchedulePHPScript(tx, id, v.ScriptSiteID); e != nil {
		return v, e
	}
	if v.Kind == "admin_script" {
		_, e = tx.Exec(`INSERT INTO schedule_scripts(schedule_id,script,timeout_seconds) VALUES(?,?,?) ON CONFLICT(schedule_id) DO UPDATE SET script=excluded.script,timeout_seconds=excluded.timeout_seconds`, id, v.Script, v.TimeoutSeconds)
	} else {
		_, e = tx.Exec(`DELETE FROM schedule_scripts WHERE schedule_id=?`, id)
	}
	if e != nil {
		return v, e
	}
	if v.RemoteID != "" {
		_, e = tx.Exec(`INSERT INTO schedule_remotes(schedule_id,remote_id) VALUES(?,?) ON CONFLICT(schedule_id) DO UPDATE SET remote_id=excluded.remote_id`, id, v.RemoteID)
	} else {
		_, e = tx.Exec(`DELETE FROM schedule_remotes WHERE schedule_id=?`, id)
	}
	if e != nil {
		return v, e
	}
	if v.Kind == "database_backup" && v.DatabaseEngine == "mariadb" {
		_, e = tx.Exec(`INSERT INTO schedule_mariadb_targets(schedule_id,database_id,instance_id,database_name,instance_name,release_id) VALUES(?,?,?,?,?,?) ON CONFLICT(schedule_id) DO UPDATE SET database_id=excluded.database_id,instance_id=excluded.instance_id,database_name=excluded.database_name,instance_name=excluded.instance_name,release_id=excluded.release_id`, id, v.TargetID, v.InstanceID, v.TargetName, v.InstanceName, v.ReleaseID)
	} else {
		_, e = tx.Exec(`DELETE FROM schedule_mariadb_targets WHERE schedule_id=?`, id)
	}
	if e != nil {
		return v, e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'schedule.update',?,'success',?)`, actor, v.Name, Now()); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	return s.Schedule(id)
}

func (s *Store) DeleteSchedule(id string, revision int64, confirm, actor string, now time.Time) error {
	v, e := s.Schedule(id)
	if e != nil {
		return errors.New("计划不存在")
	}
	if confirm != v.Name {
		return errors.New("请输入计划名称确认删除")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var active int
	if e = tx.QueryRow(`SELECT count(*) FROM schedule_runs WHERE schedule_id=? AND state IN ('queued','running')`, id).Scan(&active); e != nil {
		return e
	}
	if active != 0 {
		return errors.New("计划正在执行，不能删除")
	}
	result, e := tx.Exec(`UPDATE schedules SET enabled=0,deleted_at=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND deleted_at=0`, now.Unix(), Now(), id, revision)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("计划已变化，请刷新后重试")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'schedule.delete',?,'success',?)`, actor, v.Name, Now())
	if e != nil {
		return e
	}
	return tx.Commit()
}

func scanScheduleRun(row interface{ Scan(...any) error }) (ScheduleRun, error) {
	var v ScheduleRun
	e := row.Scan(&v.ID, &v.ScheduleID, &v.ScheduleName, &v.Trigger, &v.State, &v.ScheduledFor, &v.StartedAt, &v.FinishedAt, &v.JobID, &v.ArtifactID, &v.Error, &v.Log, &v.CreatedAt, &v.LogCleanup)
	return v, e
}

const scheduleRunSelect = `SELECT id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,job_id,artifact_id,error,log,created_at,EXISTS(SELECT 1 FROM schedule_log_operations WHERE run_id=schedule_runs.id) FROM schedule_runs`

func (s *Store) ScheduleRuns(limit int) ([]ScheduleRun, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, e := s.DB.Query(scheduleRunSelect+` ORDER BY scheduled_for DESC,rowid DESC LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ScheduleRun{}
	for rows.Next() {
		v, e := scanScheduleRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) QueueScheduleRun(id, trigger, actor string, scheduledFor time.Time) (ScheduleRun, error) {
	v, e := s.Schedule(id)
	if e != nil {
		return ScheduleRun{}, errors.New("计划不存在")
	}
	if trigger != "manual" && trigger != "scheduled" {
		return ScheduleRun{}, errors.New("运行来源无效")
	}
	if trigger == "scheduled" && !v.Enabled {
		return ScheduleRun{}, errors.New("计划已停用")
	}
	run := ScheduleRun{ID: ID(), ScheduleID: v.ID, ScheduleName: v.Name, Trigger: trigger, State: "queued", ScheduledFor: scheduledFor.Unix(), CreatedAt: Now()}
	tx, e := s.DB.Begin()
	if e != nil {
		return run, e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,created_at) VALUES(?,?,?,?,?,?,?)`, run.ID, run.ScheduleID, run.ScheduleName, run.Trigger, run.State, run.ScheduledFor, run.CreatedAt)
	if e != nil {
		return run, errors.New("该计划已有一次运行在处理")
	}
	if e = snapshotLogCleanupRun(tx, run.ID, v.ID); e != nil {
		return run, e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'schedule.run',?,'queued',?)`, actor, v.Name, Now()); e != nil {
		return run, e
	}
	if e = tx.Commit(); e != nil {
		return run, e
	}
	return run, nil
}

func (s *Store) enqueueDueSchedules(now time.Time) error {
	rows, e := s.DB.Query(`SELECT id,next_run_at FROM schedules WHERE deleted_at=0 AND enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT 20`, now.Unix())
	if e != nil {
		return e
	}
	type due struct {
		id string
		at int64
	}
	items := []due{}
	for rows.Next() {
		var v due
		if e = rows.Scan(&v.id, &v.at); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	rows.Close()
	for _, item := range items {
		v, e := s.Schedule(item.id)
		if e != nil {
			continue
		}
		next, e := nextScheduleTime(v, time.Unix(item.at, 0))
		for e == nil && !next.After(now) {
			next, e = nextScheduleTime(v, next)
		}
		if e != nil {
			continue
		}
		tx, e := s.DB.Begin()
		if e != nil {
			continue
		}
		var active int
		_ = tx.QueryRow(`SELECT count(*) FROM schedule_runs WHERE schedule_id=? AND state IN ('queued','running')`, v.ID).Scan(&active)
		if active == 0 {
			run := ScheduleRun{ID: ID(), ScheduleID: v.ID, ScheduleName: v.Name, Trigger: "scheduled", State: "queued", ScheduledFor: item.at, CreatedAt: Now()}
			_, e = tx.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,created_at) VALUES(?,?,?,?,?,?,?)`, run.ID, run.ScheduleID, run.ScheduleName, run.Trigger, run.State, run.ScheduledFor, run.CreatedAt)
			if e == nil {
				e = snapshotLogCleanupRun(tx, run.ID, v.ID)
			}
		} else {
			_, e = tx.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,finished_at,error,log,created_at) VALUES(?,?,?,'scheduled','skipped',?,?,?, ?,?)`, ID(), v.ID, v.Name, item.at, now.Unix(), "上一次运行尚未完成", "按不重叠规则跳过本次", Now())
		}
		if e == nil {
			_, e = tx.Exec(`UPDATE schedules SET next_run_at=?,revision=revision+1,updated_at=? WHERE id=? AND next_run_at=?`, next.Unix(), Now(), v.ID, item.at)
		}
		if e == nil {
			e = tx.Commit()
		}
		_ = tx.Rollback()
	}
	return nil
}

func (s *Store) startQueuedScheduleRun(now time.Time) error {
	run, e := scanScheduleRun(s.DB.QueryRow(scheduleRunSelect + ` WHERE state='queued' ORDER BY scheduled_for,rowid LIMIT 1`))
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	v, e := s.Schedule(run.ScheduleID)
	if e != nil {
		return s.failScheduleRun(run.ID, "计划已删除或不可用", now)
	}
	if e = s.validateScheduleTarget(v); e != nil {
		return s.failScheduleRun(run.ID, e.Error(), now)
	}
	scriptRelease := ""
	if v.ScriptSiteID != "" {
		site, err := s.Site(v.ScriptSiteID)
		if err != nil {
			return s.failScheduleRun(run.ID, err.Error(), now)
		}
		scriptRelease = site.PHPVersionID
	}
	if v.Kind == "site_backup" || v.Kind == "log_cleanup" || v.Kind == "admin_script" || (v.Kind == "database_backup" && v.DatabaseEngine == "mariadb") {
		artifactID := ID()
		message := "已固定网站和备份身份，准备归档公开文件"
		if v.Kind == "log_cleanup" {
			artifactID = ""
			message = "已固定网站和日志保留天数，准备轮转清理"
		}
		if v.Kind == "admin_script" {
			artifactID = ""
			message = "已固定脚本内容与受限运行身份，准备单次执行"
			if v.ScriptSiteID != "" {
				message = "已固定网站、PHP 精确版本及脚本路径，准备单次执行"
			}
		}
		if v.Kind == "database_backup" && v.DatabaseEngine == "mariadb" {
			message = "已固定 MariaDB 数据库、实例、精确版本和备份身份"
		}
		tx, e := s.DB.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		result, e := tx.Exec(`UPDATE schedule_runs SET state='running',started_at=?,artifact_id=?,log=? WHERE id=? AND state='queued'`, now.Unix(), artifactID, message, run.ID)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return nil
		}
		if v.Kind == "log_cleanup" {
			if e = snapshotLogCleanupRun(tx, run.ID, v.ID); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(`INSERT INTO schedule_direct_jobs(run_id,state) VALUES(?,'pending')`, run.ID); e != nil {
			return e
		}
		if v.Kind == "admin_script" {
			if _, e = tx.Exec(`INSERT INTO schedule_run_scripts(run_id,script,timeout_seconds,script_sha256) VALUES(?,?,?,?)`, run.ID, v.Script, v.TimeoutSeconds, AdminScriptHash(v.Script, v.ScriptSiteID, scriptRelease)); e != nil {
				return e
			}
		}
		if v.ScriptSiteID != "" {
			if _, e = tx.Exec(`INSERT INTO schedule_run_php_scripts VALUES(?,?,?)`, run.ID, v.ScriptSiteID, scriptRelease); e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	db, _ := s.Database(v.TargetID)
	server, _ := s.DatabaseServer(db.ServerID)
	jobID, e := s.QueueDatabase(DatabaseOperation{Action: "backup_database", Server: server, Database: db}, "schedule:"+run.ID, "schedule:"+v.ID)
	if e != nil {
		return s.failScheduleRun(run.ID, e.Error(), now)
	}
	var raw string
	if e = s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, jobID).Scan(&raw); e != nil {
		return e
	}
	var op DatabaseOperation
	if e = json.Unmarshal([]byte(raw), &op); e != nil || !ValidID(op.Backup.ID) {
		return s.failScheduleRun(run.ID, "底层备份任务身份无法核对", now)
	}
	_, e = s.DB.Exec(`UPDATE schedule_runs SET state='running',started_at=?,job_id=?,artifact_id=?,log=? WHERE id=? AND state='queued'`, now.Unix(), jobID, op.Backup.ID, "已提交固定数据库备份任务", run.ID)
	return e
}

func (s *Store) failScheduleRun(id, message string, now time.Time) error {
	if len(message) > 500 {
		message = message[:500]
	}
	_, e := s.DB.Exec(`UPDATE schedule_runs SET state='failed',finished_at=?,error=?,log=? WHERE id=? AND state IN ('queued','running')`, now.Unix(), message, message, id)
	return e
}

func (s *Store) reconcileScheduleRuns(now time.Time) error {
	rows, e := s.DB.Query(scheduleRunSelect + ` WHERE state='running' ORDER BY started_at LIMIT 20`)
	if e != nil {
		return e
	}
	runs := []ScheduleRun{}
	for rows.Next() {
		v, e := scanScheduleRun(rows)
		if e != nil {
			rows.Close()
			return e
		}
		runs = append(runs, v)
	}
	rows.Close()
	for _, run := range runs {
		var state, jobError string
		if e = s.DB.QueryRow(`SELECT state,error FROM mysql_jobs WHERE id=?`, run.JobID).Scan(&state, &jobError); e != nil {
			continue
		}
		if state != "succeeded" && state != "failed" && state != "needs_attention" {
			continue
		}
		if state != "succeeded" {
			_ = s.failScheduleRun(run.ID, jobError, now)
			continue
		}
		var count int
		if e = s.DB.QueryRow(`SELECT count(*) FROM mysql_backups WHERE id=?`, run.ArtifactID).Scan(&count); e != nil || count != 1 {
			_ = s.failScheduleRun(run.ID, "底层任务完成但备份产物无法核对", now)
			continue
		}
		tx, e := s.DB.Begin()
		if e != nil {
			continue
		}
		_, e = tx.Exec(`UPDATE schedule_runs SET state='succeeded',finished_at=?,log='备份文件与 SHA-256 已由执行器核对' WHERE id=? AND state='running'`, now.Unix(), run.ID)
		if e == nil {
			_, e = tx.Exec(`INSERT OR IGNORE INTO schedule_artifacts(schedule_id,run_id,kind,artifact_id,created_at) VALUES(?,?,'database_backup',?,?)`, run.ScheduleID, run.ID, run.ArtifactID, now.Unix())
		}
		if e == nil {
			_, e = tx.Exec(`UPDATE schedules SET last_run_at=? WHERE id=?`, now.Unix(), run.ScheduleID)
		}
		if e == nil {
			e = tx.Commit()
		}
		_ = tx.Rollback()
		if e == nil {
			_ = s.queueScheduleRemote(run.ScheduleID, "database", run.ArtifactID)
		}
	}
	return nil
}

func RunScheduleWorker(ctx context.Context, s *Store, ex *ExecutorClient) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	run := func(now time.Time) {
		_ = s.reconcileScheduleRuns(now)
		_ = s.executeSiteScheduleRun(ctx, ex, now)
		_ = s.executeMariaDBScheduleRun(ctx, ex, now)
		_ = s.executeLogCleanupScheduleRun(ctx, ex, now)
		_ = s.executeAdminScriptScheduleRun(ctx, ex, now)
		_ = s.executeRemoteBackupCopy(ctx, ex, now)
		_ = s.executeMariaDBRemoteBackupCopy(ctx, ex, now)
		_ = s.cleanupScheduleRetention(ctx, ex)
		_ = s.cleanupSiteScheduleRetention(ctx, ex)
		_ = s.cleanupMariaDBScheduleRetention(ctx, ex)
		_ = s.enqueueDueSchedules(now)
		_ = s.startQueuedScheduleRun(now)
	}
	run(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			run(now)
		}
	}
}

func scheduleDescription(v Schedule) string {
	loc, _ := time.LoadLocation(v.Timezone)
	next := time.Unix(v.NextRunAt, 0).In(loc).Format("2006-01-02 15:04")
	return fmt.Sprintf("%s · 下次 %s %s", v.ScheduleType, next, v.Timezone)
}
