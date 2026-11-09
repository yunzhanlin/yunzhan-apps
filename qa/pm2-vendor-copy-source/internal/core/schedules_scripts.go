package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

// executeAdminScriptScheduleRun deliberately performs one executor request only.
// The executor persists a started receipt before invoking the script, so retrying
// an interrupted request could duplicate arbitrary side effects.
func (s *Store) executeAdminScriptScheduleRun(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var runID, scheduleID, script, sha, siteID, releaseID string
	var timeout int
	e := s.DB.QueryRow(`SELECT r.id,r.schedule_id,p.script,p.timeout_seconds,p.script_sha256,COALESCE(php.site_id,''),COALESCE(php.php_version_id,'')
FROM schedule_runs r JOIN schedules s ON s.id=r.schedule_id JOIN schedule_direct_jobs d ON d.run_id=r.id JOIN schedule_run_scripts p ON p.run_id=r.id LEFT JOIN schedule_run_php_scripts php ON php.run_id=r.id
WHERE r.state='running' AND s.kind='admin_script' AND d.state='pending' ORDER BY r.started_at,r.rowid LIMIT 1`).Scan(&runID, &scheduleID, &script, &timeout, &sha, &siteID, &releaseID)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	request := AdminScriptRequest{JobID: runID, Script: script, ScriptSHA256: sha, TimeoutSeconds: timeout, SiteID: siteID, PHPVersionID: releaseID}
	var result AdminScriptResult
	e = ex.Call(ctx, http.MethodPost, "/v1/admin-scripts/run", request, &result)
	if e != nil {
		message := e.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		tx, beginErr := s.DB.Begin()
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback()
		_, updateErr := tx.Exec(`UPDATE schedule_direct_jobs SET attempts=1,last_error=?,state='failed' WHERE run_id=? AND state='pending'`, message, runID)
		if updateErr == nil {
			_, updateErr = tx.Exec(`UPDATE schedule_runs SET state='failed',finished_at=?,error=?,log=? WHERE id=? AND state='running'`, now.Unix(), message, message, runID)
		}
		if updateErr == nil {
			_, updateErr = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.script.execute',?,'failed',?)`, runID, Now())
		}
		if updateErr == nil {
			updateErr = tx.Commit()
		}
		return updateErr
	}
	output := result.Output
	if len(output) > 64*1024 {
		output = output[:64*1024]
		result.Truncated = true
	}
	if result.Truncated {
		output += "\n[输出已截断]"
	}
	if output == "" {
		output = "脚本执行成功（无输出）"
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`UPDATE schedule_runs SET state='succeeded',finished_at=?,log=? WHERE id=? AND state='running'`, now.Unix(), output, runID)
	if e == nil {
		_, e = tx.Exec(`UPDATE schedule_direct_jobs SET attempts=1,state='completed',last_error='' WHERE run_id=? AND state='pending'`, runID)
	}
	if e == nil {
		_, e = tx.Exec(`UPDATE schedules SET last_run_at=? WHERE id=?`, now.Unix(), scheduleID)
	}
	if e == nil {
		_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('scheduler','schedule.script.execute',?,'success',?)`, runID, Now())
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
