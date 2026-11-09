package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBackupRemoteEncryptsSecretAndCompletesCopy(t *testing.T) {
	s := testStore(t)
	s.encryptionKey = []byte("0123456789abcdef0123456789abcdef")
	remote, e := s.SaveBackupRemote("", BackupRemoteInput{Name: "local dav", BaseURL: "http://127.0.0.1:19091/dav", Username: "panel", Password: "remote-secret", PathPrefix: "server-one", Enabled: true}, "admin")
	if e != nil || !remote.PasswordSet || remote.LastError != "" {
		t.Fatal("remote create", remote, e)
	}
	var cipher []byte
	if e = s.DB.QueryRow(`SELECT password_cipher FROM backup_remotes WHERE id=?`, remote.ID).Scan(&cipher); e != nil || strings.Contains(string(cipher), "remote-secret") {
		t.Fatal("remote password stored as plaintext", e)
	}
	job, e := s.CreateSite("remote site", "remote-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	_ = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID)
	backup := SiteBackup{ID: ID(), SiteID: siteID, Format: "zip", Files: 1, SourceBytes: 12, Bytes: 20, SHA256: Hash("remote-site"), CreatedAt: Now()}
	if _, e = s.DB.Exec(`INSERT INTO site_backups VALUES(?,?,?,?,?,?,?,?)`, backup.ID, backup.SiteID, backup.Format, backup.Files, backup.SourceBytes, backup.Bytes, backup.SHA256, backup.CreatedAt); e != nil {
		t.Fatal(e)
	}
	copy, e := s.QueueRemoteCopy(remote.ID, "site", backup.ID, "admin")
	if e != nil || copy.State != "pending" {
		t.Fatal("copy queue", copy, e)
	}
	calls := 0
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var request RemoteBackupRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Password != "remote-secret" || request.Site == nil || request.Site.ID != backup.ID {
			t.Fatalf("remote request identity changed: %+v", request)
		}
		result := RemoteBackupResult{RemotePath: "/server-one/site/" + siteID + "/" + backup.ID + ".zip", Bytes: backup.Bytes, SHA256: backup.SHA256}
		raw, _ := json.Marshal(result)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
	})}}
	if e = s.executeRemoteBackupCopy(t.Context(), ex, time.Now()); e != nil {
		t.Fatal(e)
	}
	finished, e := s.RemoteCopy(remote.ID, "site", backup.ID)
	if e != nil || finished.State != "succeeded" || finished.Attempts != 1 || calls != 1 || finished.RemotePath == "" {
		t.Fatal("remote copy completion", finished, calls, e)
	}
}

func TestBackupRemoteRejectsInsecurePublicHTTP(t *testing.T) {
	if _, e := validateBackupRemote(BackupRemoteInput{Name: "bad", BaseURL: "http://example.com/dav", Username: "x", Password: "x", Enabled: true}); e == nil {
		t.Fatal("public plaintext WebDAV accepted")
	}
}

func TestSuccessfulScheduledSiteBackupQueuesSelectedRemote(t *testing.T) {
	s := testStore(t)
	s.encryptionKey = []byte("0123456789abcdef0123456789abcdef")
	remote, e := s.SaveBackupRemote("", BackupRemoteInput{Name: "schedule dav", BaseURL: "https://dav.example.test/root", Username: "panel", Password: "secret", PathPrefix: "host", Enabled: true}, "admin")
	if e != nil {
		t.Fatal(e)
	}
	job, e := s.CreateSite("remote scheduled site", "remote-scheduled-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	_ = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID)
	_, _ = s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, siteID)
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	schedule, e := s.CreateSchedule(Schedule{Name: "site to dav", Kind: "site_backup", TargetID: siteID, RemoteID: remote.ID, ScheduleType: "daily", Timezone: "UTC", Hour: 4, RetentionCount: 2, Enabled: true}, "admin", base)
	if e != nil || schedule.RemoteID != remote.ID || schedule.RemoteName != remote.Name {
		t.Fatal("schedule remote mapping", schedule, e)
	}
	_, _ = s.QueueScheduleRun(schedule.ID, "manual", "admin", base)
	if e = s.startQueuedScheduleRun(base); e != nil {
		t.Fatal(e)
	}
	runs, _ := s.ScheduleRuns(5)
	artifact := runs[0].ArtifactID
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		backup := SiteBackup{ID: artifact, SiteID: siteID, Format: "zip", Files: 1, SourceBytes: 10, Bytes: 20, SHA256: Hash("scheduled-remote"), CreatedAt: Now()}
		raw, _ := json.Marshal(backup)
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
	})}}
	if e = s.executeSiteScheduleRun(t.Context(), ex, base.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	copy, e := s.RemoteCopy(remote.ID, "site", artifact)
	if e != nil || copy.State != "pending" {
		t.Fatal("remote copy not queued", copy, e)
	}
}
