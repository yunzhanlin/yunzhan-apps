package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func logCleanupScheduleFixture(t *testing.T) (*Store, Schedule, time.Time) {
	t.Helper()
	s := testStore(t)
	job, e := s.CreateSite("log safety", "log-safety", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var site string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&site); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, site); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 8, 11, 0, 0, 0, time.UTC)
	schedule, e := s.CreateSchedule(Schedule{Name: "safe log rotation", Kind: "log_cleanup", TargetID: site, ScheduleType: "daily", Timezone: "UTC", Hour: 2, RetentionCount: 14, Enabled: true}, "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	return s, schedule, now
}

func TestLogCleanupScheduleReplyLossKeepsSameRunIdentityAndParameters(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(now); e != nil {
		t.Fatal(e)
	}
	var sent []LogCleanupRequest
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var in LogCleanupRequest
		if e := json.NewDecoder(r.Body).Decode(&in); e != nil {
			t.Fatal(e)
		}
		sent = append(sent, in)
		if len(sent) == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"rotated":1,"deleted":0,"deleted_bytes":0,"files":[]}`)), Request: r}, nil
	})}}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, now.Add(time.Second)); e == nil {
		t.Fatal("reply loss swallowed")
	}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, now.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	if len(sent) != 2 || sent[0].RequestID != run.ID || sent[1].RequestID != run.ID || sent[0].Attempt != 0 || sent[1].Attempt != 1 || sent[0].SiteID != sent[1].SiteID || sent[0].RetentionDays != sent[1].RetentionDays {
		t.Fatal("unsafe retry identity", sent)
	}
	runs, e := s.ScheduleRuns(5)
	if e != nil || len(runs) != 1 || runs[0].State != "succeeded" {
		t.Fatal(runs, e)
	}
}

func TestLogCleanupScheduleQueuedAndRunningParametersAreImmutable(t *testing.T) {
	for _, state := range []string{"queued", "running"} {
		t.Run(state, func(t *testing.T) {
			s, schedule, now := logCleanupScheduleFixture(t)
			if _, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now); e != nil {
				t.Fatal(e)
			}
			if state == "running" {
				if e := s.startQueuedScheduleRun(now); e != nil {
					t.Fatal(e)
				}
			}
			for _, change := range []func(*Schedule){func(v *Schedule) { v.RetentionCount++ }, func(v *Schedule) { v.Kind = "site_backup" }} {
				copy := schedule
				change(&copy)
				if _, e := s.UpdateSchedule(schedule.ID, copy, "admin", now); e == nil || !strings.Contains(e.Error(), "不可变") {
					t.Fatal("active operation parameters changed", state, e)
				}
			}
			copy := schedule
			copy.Enabled = false
			copy.Name += " paused"
			updated, e := s.UpdateSchedule(schedule.ID, copy, "admin", now)
			if e != nil || updated.Enabled || updated.RetentionCount != schedule.RetentionCount || updated.Revision != schedule.Revision+1 {
				t.Fatal("pause altered execution identity", updated, e)
			}
			updated.RetentionCount++
			if _, e = s.UpdateSchedule(schedule.ID, updated, "admin", now); e == nil {
				t.Fatal("pause bypassed active parameter protection")
			}
		})
	}
}

func TestLogCleanupScheduleOwnCancellationDoesNotConsumeFirstAttempt(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(now); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}}
	if e = s.executeLogCleanupScheduleRun(ctx, ex, now.Add(time.Second)); e != context.Canceled {
		t.Fatal(e)
	}
	var attempts int
	var state string
	if e = s.DB.QueryRow(`SELECT attempts,state FROM schedule_direct_jobs WHERE run_id=?`, run.ID).Scan(&attempts, &state); e != nil || attempts != 0 || state != "pending" {
		t.Fatal("cancellation lost initial attempt", attempts, state, e)
	}
}

func TestLogCleanupScheduleNeverAcceptsForeignArchiveResults(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(now); e != nil {
		t.Fatal(e)
	}
	body, e := json.Marshal(LogCleanupResult{Rotated: 0, Deleted: 1, DeletedBytes: 2, Files: []string{"panel-" + ID() + ".error.log.20260801-010000"}})
	if e != nil {
		t.Fatal(e)
	}
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, now.Add(time.Second)); e == nil {
		t.Fatal("foreign deletion result accepted")
	}
	var state string
	if e = s.DB.QueryRow(`SELECT state FROM schedule_runs WHERE id=?`, run.ID).Scan(&state); e != nil || state != "running" {
		t.Fatal("invalid result marked successful", state, e)
	}
}

func TestLogCleanupScheduleSnapshotSurvivesCompletedScheduleRetargeting(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(now); e != nil {
		t.Fatal(e)
	}
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"rotated":0,"deleted":0,"deleted_bytes":0,"files":[]}`)), Request: r}, nil
	})}}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	copy := schedule
	copy.Kind = "site_backup"
	copy.RetentionCount = 3
	otherJob, e := s.CreateSite("other log site", "other-log-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, otherJob).Scan(&copy.TargetID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE sites SET status='running' WHERE id=?`, copy.TargetID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.UpdateSchedule(schedule.ID, copy, "admin", now); e != nil {
		t.Fatal("completed schedule cannot be edited", e)
	}
	var site string
	var days int
	if e = s.DB.QueryRow(`SELECT site_id,retention_days FROM schedule_log_operations WHERE run_id=?`, run.ID).Scan(&site, &days); e != nil || site != schedule.TargetID || days != 14 {
		t.Fatal("history followed edited schedule", site, days, e)
	}
	runs, e := s.ScheduleRuns(5)
	if e != nil || len(runs) != 1 || !runs[0].LogCleanup {
		t.Fatal("historical log inspection flag disappeared", runs, e)
	}
}

func TestLogCleanupScheduleLegacyInFlightWithoutSnapshotNeverCallsExecutor(t *testing.T) {
	s, schedule, now := logCleanupScheduleFixture(t)
	run, e := s.QueueScheduleRun(schedule.ID, "manual", "admin", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.startQueuedScheduleRun(now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`DELETE FROM schedule_log_operations WHERE run_id=?`, run.ID); e != nil {
		t.Fatal(e)
	}
	called := false
	ex := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) { called = true; return nil, io.ErrUnexpectedEOF })}}
	if e = s.executeLogCleanupScheduleRun(t.Context(), ex, now.Add(time.Second)); e != nil || called {
		t.Fatal("legacy uncertain job executed", e, called)
	}
	runs, e := s.ScheduleRuns(5)
	if e != nil || runs[0].State != "failed" || !strings.Contains(runs[0].Error, "旧版本") {
		t.Fatal(runs, e)
	}
}
