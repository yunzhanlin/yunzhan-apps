package core

import (
	"context"
	"database/sql"
	"errors"
)

// A cleanup which has crossed the durable dispatch boundary is never picked
// again automatically. This uses the existing attempts column: older failures
// remain untouched and a lost executor reply cannot turn into another DELETE.
const scheduleCleanupUnconfirmed = "清理请求已登记，执行结果尚未确认；原备份与记录需核对，不自动重复执行"

func retentionTable(engine string) (string, error) {
	switch engine {
	case "mysql":
		return "schedule_cleanup_jobs", nil
	case "mariadb":
		return "mariadb_schedule_cleanup_jobs", nil
	case "site":
		return "site_schedule_cleanup_jobs", nil
	default:
		return "", errors.New("备份清理类型无效")
	}
}

// Ranking includes every original backup, including a failed cleanup's backup.
// A held or failed item must not make a newer retained backup become eligible.
// Remote copies must finish before their local source can be removed.
func eligibleRetentionArtifactsSQL(engine string) (string, error) {
	var backups, kind, remote string
	switch engine {
	case "mysql":
		backups, kind = "mysql_backups", "database_backup"
		remote = `NOT EXISTS(SELECT 1 FROM backup_remote_copies rc WHERE rc.artifact_kind='database' AND rc.artifact_id=ranked.artifact_id AND rc.state!='succeeded')`
	case "mariadb":
		backups, kind = "mariadb_schedule_backups", "mariadb_backup"
		remote = `NOT EXISTS(SELECT 1 FROM mariadb_remote_copies rc WHERE rc.artifact_id=ranked.artifact_id AND rc.state!='succeeded')`
	case "site":
		backups, kind = "site_backups", "site_backup"
		remote = `NOT EXISTS(SELECT 1 FROM backup_remote_copies rc WHERE rc.artifact_kind='site' AND rc.artifact_id=ranked.artifact_id AND rc.state!='succeeded')`
	default:
		return "", errors.New("备份清理类型无效")
	}
	return `WITH ranked AS (
SELECT sa.artifact_id,s.retention_count,
ROW_NUMBER() OVER(PARTITION BY sa.schedule_id ORDER BY sa.created_at DESC,sa.artifact_id DESC) position
FROM schedule_artifacts sa JOIN schedules s ON s.id=sa.schedule_id JOIN ` + backups + ` b ON b.id=sa.artifact_id
WHERE sa.kind='` + kind + `' AND s.enabled=1 AND s.deleted_at=0)
SELECT artifact_id FROM ranked WHERE position>retention_count AND ` + remote, nil
}

// All callers below use compile-time engine names, never an HTTP value.
func mustEligibleRetentionSQL(engine string) string {
	query, err := eligibleRetentionArtifactsSQL(engine)
	if err != nil {
		panic("invalid internal retention engine")
	}
	return query
}

func completeScheduleCleanup(tx *sql.Tx, engine, id string) error {
	table, err := retentionTable(engine)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE `+table+` SET state='completed',last_error='',completed_at=? WHERE artifact_id=? AND state='pending' AND attempts=1 AND last_error=?`, Now(), id, scheduleCleanupUnconfirmed)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("清理登记已变化，执行结果保留待核对")
	}
	return nil
}

func readyRetentionPredicate(engine string) (string, error) {
	eligible, err := eligibleRetentionArtifactsSQL(engine)
	if err != nil {
		return "", err
	}
	identity, err := retentionBackupIdentitySQL(engine)
	if err != nil {
		return "", err
	}
	return `state='pending' AND attempts=0 AND last_error='' AND ` + identity + ` AND artifact_id IN (` + eligible + `)`, nil
}

func retentionBackupIdentitySQL(engine string) (string, error) {
	table, err := retentionTable(engine)
	if err != nil {
		return "", err
	}
	var backups string
	var columns []string
	switch engine {
	case "mysql":
		backups = "mysql_backups"
		columns = []string{"database_id", "server_id", "version", "bytes", "sha256"}
	case "mariadb":
		backups = "mariadb_schedule_backups"
		columns = []string{"database_id", "instance_id", "bytes", "sha256"}
	case "site":
		backups = "site_backups"
		columns = []string{"site_id", "bytes", "sha256"}
	}
	query := `EXISTS(SELECT 1 FROM ` + backups + ` b WHERE b.id=` + table + `.artifact_id`
	for _, column := range columns {
		query += ` AND b.` + column + `=` + table + `.` + column
	}
	query += `) AND EXISTS(SELECT 1 FROM schedule_artifacts sa WHERE sa.artifact_id=` + table + `.artifact_id AND sa.schedule_id=` + table + `.schedule_id)`
	return query, nil
}

type scheduleCleanupIdentity struct {
	Engine, ArtifactID, ScheduleID, SHA256, DatabaseID, ServerID, Version, SiteID string
	Bytes                                                                         int64
}

func (v scheduleCleanupIdentity) predicate() (string, []any, error) {
	if !ValidID(v.ArtifactID) || !ValidID(v.ScheduleID) || !validLowerSHA256(v.SHA256) || v.Bytes < 0 {
		return "", nil, errors.New("备份清理身份无效")
	}
	where := `artifact_id=? AND schedule_id=? AND bytes=? AND sha256=?`
	args := []any{v.ArtifactID, v.ScheduleID, v.Bytes, v.SHA256}
	switch v.Engine {
	case "mysql":
		where += ` AND database_id=? AND server_id=? AND version=?`
		args = append(args, v.DatabaseID, v.ServerID, v.Version)
	case "mariadb":
		where += ` AND database_id=? AND instance_id=?`
		args = append(args, v.DatabaseID, v.ServerID)
	case "site":
		where += ` AND site_id=?`
		args = append(args, v.SiteID)
	default:
		return "", nil, errors.New("备份清理类型无效")
	}
	return where, args, nil
}

func (s *Store) reserveScheduleCleanup(ctx context.Context, v scheduleCleanupIdentity) (bool, error) {
	table, err := retentionTable(v.Engine)
	if err != nil {
		return false, err
	}
	ready, err := readyRetentionPredicate(v.Engine)
	if err != nil {
		return false, err
	}
	identity, args, err := v.predicate()
	if err != nil {
		return false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	args = append([]any{scheduleCleanupUnconfirmed}, args...)
	result, err := tx.ExecContext(ctx, `UPDATE `+table+` SET attempts=1,last_error=? WHERE `+identity+` AND `+ready, args...)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if n != 1 {
		return false, errors.New("备份清理登记数异常")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.retention.dispatch',?,'一次清理已登记；未确认结果不自动重放',?)`, v.Engine+":"+v.ArtifactID, Now())
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// Failure diagnostics may be appended after dispatch, but never reset attempts
// or erase a previous failure to make an old operation eligible again.
func (s *Store) recordScheduleCleanupFailure(ctx context.Context, engine, id, message string) error {
	table, err := retentionTable(engine)
	if err != nil {
		return err
	}
	if len(message) > 500 {
		message = message[:500]
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE `+table+` SET last_error=? WHERE artifact_id=? AND state='pending' AND attempts=1 AND last_error=?`, message, id, scheduleCleanupUnconfirmed)
	return err
}
