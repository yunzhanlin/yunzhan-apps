package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func TestManualSiteBackupQueueRecoveryAndResult(t *testing.T) {
	s := testStore(t)
	createJob, err := s.CreateSite("backup target", "backup-target", ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	var siteID string
	if err = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, createJob).Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	_, _ = s.DB.Exec(`UPDATE jobs SET state='succeeded' WHERE id=?`, createJob)
	_, _ = s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID)
	if _, err = s.QueueSiteBackup(siteID, "wrong", "backup-key", "admin"); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	jobID, err := s.QueueSiteBackup(siteID, "backup target", "backup-key", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if replay, e := s.QueueSiteBackup(siteID, "backup target", "backup-key", "admin"); e != nil || replay != jobID {
		t.Fatal("backup idempotency failed", replay, e)
	}
	if _, err = s.NextJob(); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("site config worker claimed backup", err)
	}
	job, err := s.NextSiteBackupJob()
	if err != nil || job.ID != jobID {
		t.Fatal("backup worker claim failed", job, err)
	}
	if err = s.Recover(); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = s.DB.QueryRow(`SELECT status FROM sites WHERE id=?`, siteID).Scan(&status); err != nil || status != "running" {
		t.Fatal("backup restart altered site status", status, err)
	}
	job, err = s.NextSiteBackupJob()
	if err != nil || job.ID != jobID {
		t.Fatal("backup not requeued after restart", job, err)
	}
	var payload JobPayload
	if err = json.Unmarshal([]byte(job.Payload), &payload); err != nil || payload.SiteBackup == nil {
		t.Fatal("backup payload invalid", err)
	}
	backup := SiteBackup{ID: payload.SiteBackup.ID, SiteID: siteID, Format: "zip", Files: 2, SourceBytes: 50, Bytes: 70, SHA256: Hash("archive"), CreatedAt: Now()}
	if err = s.FinishSiteBackupJob(job, backup, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := s.SiteBackup(backup.ID)
	if err != nil || stored.SHA256 != backup.SHA256 {
		t.Fatal("backup result was not recorded", stored, err)
	}
	if err = s.DB.QueryRow(`SELECT state FROM jobs WHERE id=?`, jobID).Scan(&status); err != nil || status != "succeeded" {
		t.Fatal("backup job not complete", status, err)
	}
}

func TestQueueSiteRestoreChecksConfirmationAndIdempotency(t *testing.T) {
	s := testStore(t)
	createJob, e := s.CreateSite("restore target", "restore-target", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, createJob).Scan(&siteID)
	s.DB.Exec(`UPDATE jobs SET state='succeeded' WHERE id=?`, createJob)
	s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID)
	backup := SiteBackup{ID: ID(), SiteID: siteID, Format: "zip", Files: 2, SourceBytes: 50, Bytes: 80, SHA256: Hash("site-backup"), CreatedAt: Now()}
	if _, e = s.DB.Exec(`INSERT INTO site_backups VALUES(?,?,?,?,?,?,?,?)`, backup.ID, backup.SiteID, backup.Format, backup.Files, backup.SourceBytes, backup.Bytes, backup.SHA256, backup.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteRestore(backup.ID, "wrong", "restore-key", "admin"); e == nil {
		t.Fatal("wrong site confirmation accepted")
	}
	jobID, e := s.QueueSiteRestore(backup.ID, "restore target", "restore-key", "admin")
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.QueueSiteRestore(backup.ID, "restore target", "restore-key", "admin")
	if e != nil || replay != jobID {
		t.Fatal("restore idempotency failed", replay, e)
	}
	var kind, payload string
	if e = s.DB.QueryRow(`SELECT kind,payload FROM jobs WHERE id=?`, jobID).Scan(&kind, &payload); e != nil {
		t.Fatal(e)
	}
	var decoded JobPayload
	if kind != "restore_site" || json.Unmarshal([]byte(payload), &decoded) != nil || decoded.SiteBackup == nil || decoded.SiteBackup.ID != backup.ID || decoded.PreviousStatus != "running" {
		t.Fatal("restore payload changed", kind, payload)
	}
}
