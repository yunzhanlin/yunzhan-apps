package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"strings"
	"testing"
	"time"
)

type scheduleRoundTripFunc func(*http.Request) (*http.Response, error)

func (f scheduleRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func scheduleDatabaseFixture(t *testing.T, s *Store) (DatabaseServer, Database) {
	t.Helper()
	release, _ := runtimecatalog.Find("mysql-8.4.11")
	if e := s.RecordInstallation(release, "arm64"); e != nil {
		t.Fatal(e)
	}
	server := DatabaseServer{ID: ID(), Name: "schedule mysql", ReleaseID: release.ID, Port: 13306, Status: "running", CreatedAt: Now()}
	db := Database{ID: ID(), ServerID: server.ID, Name: "schedule_data", Username: "db_schedule", Status: "ready", CreatedAt: Now()}
	if _, e := s.DB.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, server.ID, server.Name, server.ReleaseID, server.Port, server.Status, server.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, db.ID, db.ServerID, db.Name, db.Username, db.Status, db.CreatedAt); e != nil {
		t.Fatal(e)
	}
	return server, db
}

func TestScheduleNextTimeAndDST(t *testing.T) {
	v := Schedule{Name: "test", Kind: "database_backup", TargetID: ID(), ScheduleType: "daily", Timezone: "Asia/Shanghai", Hour: 3, Minute: 15, Weekday: 1, RetentionCount: 3}
	next, e := nextScheduleTime(v, time.Date(2026, 9, 19, 20, 0, 0, 0, time.FixedZone("CST", 8*3600)))
	if e != nil || next.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04") != "2026-09-20 03:15" {
		t.Fatal("daily next time", next, e)
	}
	v.ScheduleType, v.Timezone, v.Hour, v.Minute = "daily", "America/New_York", 2, 30
	next, e = nextScheduleTime(v, time.Date(2026, 3, 8, 0, 0, 0, 0, time.FixedZone("EST", -5*3600)))
	loc, _ := time.LoadLocation(v.Timezone)
	if e != nil || next.In(loc).Format("2006-01-02 15:04") != "2026-03-08 03:00" {
		t.Fatal("nonexistent DST time did not advance to first valid minute", next.In(loc), e)
	}
	v.ScheduleType, v.Hour, v.Minute, v.Weekday = "weekly", 8, 5, 1
	next, e = nextScheduleTime(v, time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
	if e != nil || next.In(loc).Weekday() != time.Monday || next.In(loc).Hour() != 8 || next.In(loc).Minute() != 5 {
		t.Fatal("weekly next time", next.In(loc), e)
	}
}

func TestAdminScriptScheduleSnapshotsAndRunsOnce(t *testing.T) {
	s := testStore(t)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	original := "#!/bin/bash\necho original\n"
	v, e := s.CreateSchedule(Schedule{Name: "safe script", Kind: "admin_script", TargetID: strings.Repeat("0", 32), Script: original, TimeoutSeconds: 12, ScheduleType: "daily", Timezone: "UTC", Hour: 3, RetentionCount: 1, Enabled: true}, "admin", base)
	if e != nil || v.Script != original || v.TargetName != "受限 panel-task 用户" {
		t.Fatal("admin script creation", v, e)
	}
	if _, e = s.QueueScheduleRun(v.ID, "manual", "admin", base); e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(base.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE schedule_scripts SET script='echo changed',timeout_seconds=30 WHERE schedule_id=?`, v.ID); e != nil {
		t.Fatal(e)
	}
	calls := 0
	client := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var in AdminScriptRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Script != original || in.ScriptSHA256 != Hash(original) || in.TimeoutSeconds != 12 {
			t.Fatalf("queued script identity changed: %+v", in)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"state":"completed","output":"original output","started_at":"2026-09-19T12:00:01Z","finished_at":"2026-09-19T12:00:02Z"}`)), Header: make(http.Header)}, nil
	})}}
	if e = s.executeAdminScriptScheduleRun(context.Background(), client, base.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = s.executeAdminScriptScheduleRun(context.Background(), client, base.Add(3*time.Second)); e != nil || calls != 1 {
		t.Fatal("completed script ran more than once", calls, e)
	}
	runs, _ := s.ScheduleRuns(5)
	if runs[0].State != "succeeded" || runs[0].Log != "original output" {
		t.Fatal("script result not persisted", runs[0])
	}
}

func TestAdminScriptFailureIsNotRetried(t *testing.T) {
	s := testStore(t)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	v, e := s.CreateSchedule(Schedule{Name: "failing script", Kind: "admin_script", TargetID: strings.Repeat("0", 32), Script: "exit 7\n", TimeoutSeconds: 5, ScheduleType: "hourly", Timezone: "UTC", RetentionCount: 1, Enabled: true}, "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = s.QueueScheduleRun(v.ID, "manual", "admin", base)
	_ = s.startQueuedScheduleRun(base.Add(time.Second))
	calls := 0
	client := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader(`{"error":"脚本返回失败: exit status 7"}`)), Header: make(http.Header)}, nil
	})}}
	if e = s.executeAdminScriptScheduleRun(context.Background(), client, base.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	_ = s.executeAdminScriptScheduleRun(context.Background(), client, base.Add(5*time.Second))
	if calls != 1 {
		t.Fatal("failed script was retried", calls)
	}
	runs, _ := s.ScheduleRuns(5)
	if runs[0].State != "failed" {
		t.Fatal("failed script state missing", runs[0])
	}
}

func TestScheduleRevisionNonOverlapAndDatabaseCompletion(t *testing.T) {
	s := testStore(t)
	server, db := scheduleDatabaseFixture(t, s)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	input := Schedule{Name: "daily database", Kind: "database_backup", TargetID: db.ID, ScheduleType: "daily", Timezone: "Asia/Shanghai", Hour: 3, Minute: 15, Weekday: 1, RetentionCount: 2, Enabled: true}
	created, e := s.CreateSchedule(input, "admin", base)
	if e != nil || !ValidID(created.ID) || created.Revision != 1 || created.TargetName != db.Name || created.NextRunAt <= base.Unix() {
		t.Fatal("schedule creation", created, e)
	}
	stale := created
	stale.Revision = 99
	if _, e = s.UpdateSchedule(created.ID, stale, "admin", base); e == nil {
		t.Fatal("stale schedule revision accepted")
	}
	run, e := s.QueueScheduleRun(created.ID, "manual", "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueScheduleRun(created.ID, "manual", "admin", base); e == nil {
		t.Fatal("overlapping schedule run accepted")
	}
	if e = s.startQueuedScheduleRun(base.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	runs, _ := s.ScheduleRuns(20)
	if len(runs) != 1 || runs[0].State != "running" || !ValidID(runs[0].JobID) || !ValidID(runs[0].ArtifactID) {
		t.Fatal("scheduled backup not linked", runs)
	}
	var raw string
	s.DB.QueryRow(`SELECT payload FROM mysql_jobs WHERE id=?`, runs[0].JobID).Scan(&raw)
	var op DatabaseOperation
	if json.Unmarshal([]byte(raw), &op) != nil || op.Server.ID != server.ID || op.Database.ID != db.ID || op.Backup.ID != runs[0].ArtifactID {
		t.Fatal("scheduled task changed backup identity", raw)
	}
	backup := op.Backup
	backup.Version, backup.Bytes, backup.SHA256 = "8.4.11", 123, Hash("backup")
	if e = s.FinishDatabase(op, DatabaseResult{State: "succeeded", Backup: backup}); e != nil {
		t.Fatal(e)
	}
	if e = s.reconcileScheduleRuns(base.Add(3 * time.Second)); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.ScheduleRuns(20)
	if runs[0].ID != run.ID || runs[0].State != "succeeded" || runs[0].ArtifactID != backup.ID {
		t.Fatal("successful backup not reconciled", runs[0])
	}
	var artifacts int
	s.DB.QueryRow(`SELECT count(*) FROM schedule_artifacts WHERE schedule_id=? AND artifact_id=?`, created.ID, backup.ID).Scan(&artifacts)
	if artifacts != 1 {
		t.Fatal("scheduled artifact not retained")
	}
	if e = s.DeleteSchedule(created.ID, created.Revision, "wrong", "admin", base); e == nil {
		t.Fatal("schedule deletion without name confirmation")
	}
}

func TestDueScheduleAdvancesAndSkipsOverlap(t *testing.T) {
	s := testStore(t)
	_, db := scheduleDatabaseFixture(t, s)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	v, e := s.CreateSchedule(Schedule{Name: "hourly", Kind: "database_backup", TargetID: db.ID, ScheduleType: "hourly", Timezone: "UTC", Minute: 5, RetentionCount: 2, Enabled: true}, "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, base.Add(-3*time.Hour).Unix(), v.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.enqueueDueSchedules(base); e != nil {
		t.Fatal(e)
	}
	current, _ := s.Schedule(v.ID)
	if current.NextRunAt <= base.Unix() {
		t.Fatal("missed schedule did not advance to future", current.NextRunAt)
	}
	runs, _ := s.ScheduleRuns(20)
	if len(runs) != 1 || runs[0].State != "queued" {
		t.Fatal("missed schedule did not queue once", runs)
	}
	if _, e = s.DB.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, base.Add(-time.Hour).Unix(), v.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.enqueueDueSchedules(base); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.ScheduleRuns(20)
	if len(runs) != 2 || runs[0].State != "skipped" || runs[1].State != "queued" {
		t.Fatal("overlap was not recorded as one skipped run", runs)
	}
}

func TestScheduleRetentionRetriesVerifiedDeletion(t *testing.T) {
	s := testStore(t)
	server, db := scheduleDatabaseFixture(t, s)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	v, e := s.CreateSchedule(Schedule{Name: "retain two", Kind: "database_backup", TargetID: db.ID, ScheduleType: "daily", Timezone: "UTC", Hour: 3, Minute: 5, RetentionCount: 2, Enabled: true}, "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{ID(), ID(), ID()}
	for i, id := range ids {
		created := base.Add(time.Duration(i) * time.Hour)
		runID := ID()
		sha := Hash(id)
		if _, e = s.DB.Exec(`INSERT INTO mysql_backups VALUES(?,?,?,?,?,?,?)`, id, db.ID, server.ID, "8.4.11", int64(100+i), sha, created.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,artifact_id,created_at) VALUES(?,?,?,'scheduled','succeeded',?,?,?,?,?)`, runID, v.ID, v.Name, created.Unix(), created.Unix(), created.Unix(), id, created.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(`INSERT INTO schedule_artifacts VALUES(?,?,'database_backup',?,?)`, v.ID, runID, id, created.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	calls := 0
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodDelete || !strings.Contains(r.URL.Path, ids[0]) || r.URL.Query().Get("database_id") != db.ID || len(r.URL.Query().Get("sha256")) != 64 {
			t.Fatalf("unexpected retention request: %s %s", r.Method, r.URL.String())
		}
		status, body := http.StatusConflict, `{"error":"temporary"}`
		if calls > 1 {
			status, body = http.StatusOK, `{"deleted":true}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}}
	if e = s.cleanupScheduleRetention(t.Context(), ex); e == nil {
		t.Fatal("failed executor deletion was accepted")
	}
	var backups, attempts int
	s.DB.QueryRow(`SELECT count(*) FROM mysql_backups`).Scan(&backups)
	s.DB.QueryRow(`SELECT attempts FROM schedule_cleanup_jobs WHERE artifact_id=?`, ids[0]).Scan(&attempts)
	if backups != 3 || attempts != 1 {
		t.Fatal("failed cleanup changed records", backups, attempts)
	}
	if e = s.cleanupScheduleRetention(t.Context(), ex); e != nil {
		t.Fatal(e)
	}
	var state string
	s.DB.QueryRow(`SELECT count(*) FROM mysql_backups`).Scan(&backups)
	s.DB.QueryRow(`SELECT state FROM schedule_cleanup_jobs WHERE artifact_id=?`, ids[0]).Scan(&state)
	if calls != 2 || backups != 2 || state != "completed" {
		t.Fatal("retention did not complete idempotently", calls, backups, state)
	}
}

func TestMariaDBRetentionWaitsForRemoteCopy(t *testing.T) {
	s := testStore(t)
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	scheduleID, databaseID, instanceID, remoteID := ID(), ID(), ID(), ID()
	if _, e := s.DB.Exec(`INSERT INTO schedules(id,name,kind,target_id,schedule_type,timezone,minute,hour,weekday,retention_count,enabled,revision,next_run_at,created_at,updated_at) VALUES(?,?,'database_backup',?,'daily','UTC',0,3,1,1,1,1,?,?,?)`, scheduleID, "MariaDB remote retention", databaseID, base.Add(time.Hour).Unix(), base.Format(time.RFC3339), base.Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`INSERT INTO backup_remotes(id,name,base_url,username,password_cipher,path_prefix,enabled,created_at,updated_at) VALUES(?,?,'https://example.invalid/dav','test',?,'panel',1,?,?)`, remoteID, "retention remote", []byte{1}, base.Format(time.RFC3339), base.Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	ids := []string{ID(), ID()}
	for i, id := range ids {
		at := base.Add(time.Duration(i) * time.Hour)
		runID := ID()
		if _, e := s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,artifact_id,created_at) VALUES(?,?,?,'scheduled','succeeded',?,?,?,?,?)`, runID, scheduleID, "MariaDB remote retention", at.Unix(), at.Unix(), at.Unix(), id, at.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e := s.DB.Exec(`INSERT INTO mariadb_schedule_backups(id,database_id,instance_id,database_name,instance_name,release_id,bytes,sha256,created_at) VALUES(?,?,?,?,?,'mariadb-11.8.9',?,?,?)`, id, databaseID, instanceID, "app", "main", int64(100+i), Hash(id), at.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e := s.DB.Exec(`INSERT INTO schedule_artifacts VALUES(?,?,'mariadb_backup',?,?)`, scheduleID, runID, id, at.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.DB.Exec(`INSERT INTO mariadb_remote_copies(id,remote_id,artifact_id,bytes,sha256,state,attempts,error,created_at) VALUES(?,?,?,?,?,'failed',3,'remote unavailable',?)`, ID(), remoteID, ids[0], 100, Hash(ids[0]), base.Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.claimMariaDBScheduleCleanup(); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("failed remote copy did not protect the local backup", e)
	}
	if _, e := s.DB.Exec(`UPDATE mariadb_remote_copies SET state='succeeded',error='',completed_at=? WHERE artifact_id=?`, Now(), ids[0]); e != nil {
		t.Fatal(e)
	}
	cleanup, e := s.claimMariaDBScheduleCleanup()
	if e != nil || cleanup.Backup.ID != ids[0] {
		t.Fatal("verified remote copy did not release the old local backup", cleanup, e)
	}
}

func TestSiteScheduleUsesFixedArtifactAndCompletes(t *testing.T) {
	s := testStore(t)
	jobID, e := s.CreateSite("scheduled site", "scheduled-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, jobID).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID); e != nil {
		t.Fatal(e)
	}
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	schedule, e := s.CreateSchedule(Schedule{Name: "site files", Kind: "site_backup", TargetID: siteID, ScheduleType: "daily", Timezone: "UTC", Hour: 4, Minute: 10, RetentionCount: 3, Enabled: true}, "admin", base)
	if e != nil || schedule.TargetName != "scheduled site" {
		t.Fatal("site schedule creation", schedule, e)
	}
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", base)
	if e != nil || s.startQueuedScheduleRun(base) != nil {
		t.Fatal("site schedule queue", run, e)
	}
	runs, _ := s.ScheduleRuns(10)
	if len(runs) != 1 || runs[0].State != "running" || !ValidID(runs[0].ArtifactID) || runs[0].JobID != "" {
		t.Fatal("site schedule did not fix direct artifact", runs)
	}
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var in SiteBackup
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil || in.ID != runs[0].ArtifactID || in.SiteID != siteID {
			t.Fatalf("unexpected site backup request: %s %s", r.Method, r.URL.String())
		}
		in.Format, in.Files, in.SourceBytes, in.Bytes, in.SHA256, in.CreatedAt = "zip", 4, 512, 300, Hash("site"), Now()
		raw, _ := json.Marshal(in)
		return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})}}
	if e = s.executeSiteScheduleRun(t.Context(), ex, base.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	runs, _ = s.ScheduleRuns(10)
	if runs[0].State != "succeeded" || runs[0].ArtifactID == "" {
		t.Fatal("site schedule did not complete", runs[0])
	}
	var backups, artifacts int
	s.DB.QueryRow(`SELECT count(*) FROM site_backups WHERE id=? AND site_id=?`, runs[0].ArtifactID, siteID).Scan(&backups)
	s.DB.QueryRow(`SELECT count(*) FROM schedule_artifacts WHERE run_id=? AND kind='site_backup'`, run.ID).Scan(&artifacts)
	if backups != 1 || artifacts != 1 {
		t.Fatal("site backup metadata missing", backups, artifacts)
	}
}

func TestSiteScheduleRetentionDeletesOnlyOldestArtifact(t *testing.T) {
	s := testStore(t)
	jobID, e := s.CreateSite("retained site", "retained-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, jobID).Scan(&siteID)
	s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	schedule, e := s.CreateSchedule(Schedule{Name: "retain site two", Kind: "site_backup", TargetID: siteID, ScheduleType: "daily", Timezone: "UTC", Hour: 4, Minute: 10, RetentionCount: 2, Enabled: true}, "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{ID(), ID(), ID()}
	for index, id := range ids {
		at := base.Add(time.Duration(index) * time.Hour)
		runID := ID()
		if _, e = s.DB.Exec(`INSERT INTO site_backups VALUES(?,?,?, ?,?,?,?,?)`, id, siteID, "zip", 2, 20, int64(100+index), Hash(id), at.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,artifact_id,created_at) VALUES(?,?,?,'scheduled','succeeded',?,?,?,?,?)`, runID, schedule.ID, schedule.Name, at.Unix(), at.Unix(), at.Unix(), id, at.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(`INSERT INTO schedule_artifacts VALUES(?,?,'site_backup',?,?)`, schedule.ID, runID, id, at.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodDelete || !strings.Contains(r.URL.Path, ids[0]) || r.URL.Query().Get("sha256") != Hash(ids[0]) {
			t.Fatalf("unexpected site retention request: %s", r.URL.String())
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"deleted":true}`)), Request: r}, nil
	})}}
	if e = s.cleanupSiteScheduleRetention(t.Context(), ex); e != nil {
		t.Fatal(e)
	}
	var backups, artifacts int
	s.DB.QueryRow(`SELECT count(*) FROM site_backups`).Scan(&backups)
	s.DB.QueryRow(`SELECT count(*) FROM schedule_artifacts WHERE schedule_id=?`, schedule.ID).Scan(&artifacts)
	if backups != 2 || artifacts != 2 {
		t.Fatal("site retention count mismatch", backups, artifacts)
	}
}

func TestLogCleanupScheduleUsesFixedSiteAndRetentionDays(t *testing.T) {
	s := testStore(t)
	createJob, e := s.CreateSite("logs site", "logs-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, createJob).Scan(&siteID)
	s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	schedule, e := s.CreateSchedule(Schedule{Name: "clean logs", Kind: "log_cleanup", TargetID: siteID, ScheduleType: "daily", Timezone: "UTC", Hour: 2, Minute: 0, RetentionCount: 14, Enabled: true}, "admin", base)
	if e != nil {
		t.Fatal(e)
	}
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", base)
	if e != nil || s.startQueuedScheduleRun(base) != nil {
		t.Fatal(run, e)
	}
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var in LogCleanupRequest
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil || in.SiteID != siteID || in.RetentionDays != 14 {
			t.Fatalf("unexpected log cleanup request: %s", r.URL.String())
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"rotated":2,"deleted":3,"deleted_bytes":512,"files":[]}`)), Request: r}, nil
	})}}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, base.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	runs, _ := s.ScheduleRuns(10)
	if len(runs) != 1 || runs[0].ID != run.ID || runs[0].State != "succeeded" || !strings.Contains(runs[0].Log, "删除 3 个") || runs[0].ArtifactID != "" {
		t.Fatal("log cleanup schedule result", runs)
	}
}
