package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
)

func TestDailyReportSchedulePreservesReportsAndRejectsStaleEdits(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	revision := int64(0)
	initial, err := readDailyReportSchedule(ctx, s.DB)
	if err != nil || initial != defaultDailyReportSchedule() {
		t.Fatalf("unexpected default schedule: %+v %v", initial, err)
	}
	old := map[string]any{"created_at": "2026-11-11T22:00:00Z", "sites": 4}
	if err := s.saveDailyReportRecord(ctx, "2026-11-11", old); err != nil {
		t.Fatal(err)
	}
	next, err := s.updateDailyReportSchedule(ctx, dailyReportScheduleUpdate{TimeZone: "America/New_York", LocalTime: "08:05", ExpectedRevision: &revision}, "qa")
	if err != nil || next.Revision != 1 {
		t.Fatalf("schedule was not saved: %+v, %v", next, err)
	}
	if _, err = s.updateDailyReportSchedule(ctx, dailyReportScheduleUpdate{TimeZone: "UTC", LocalTime: "09:00", ExpectedRevision: &revision}, "qa"); !errors.Is(err, errDailyReportScheduleChanged) {
		t.Fatalf("stale edit changed the schedule: %v", err)
	}
	if _, err = s.updateDailyReportSchedule(ctx, dailyReportScheduleUpdate{TimeZone: "Local", LocalTime: "08:00", ExpectedRevision: &next.Revision}, "qa"); err == nil {
		t.Fatal("process-local time zone was accepted")
	}
	if _, report, err := readDailyReportRecord(ctx, s.DB, "2026-11-11"); err != nil || report["created_at"] != old["created_at"] {
		t.Fatalf("old report changed after schedule edit: %+v, %v", report, err)
	}
	if err := s.saveDailyReportRecordWithSchedule(ctx, "2026-11-12", old, &revision, true); !errors.Is(err, errDailyReportScheduleChanged) {
		t.Fatalf("report used a schedule which was edited during sampling: %v", err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='daily-report.schedule'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unexpected schedule audit records: %d, %v", count, err)
	}
}

func TestDailyWorkerRespectsConfiguredLocalTimeAndDeduplicates(t *testing.T) {
	rows := dailyWorkerInstalled()
	rows[0].Version = appcatalog.DailyReportScheduleVersion
	a, observations := dailyWorkerFixture(t, rows, false)
	ctx := context.Background()
	revision := int64(0)
	if _, err := a.Store.updateDailyReportSchedule(ctx, dailyReportScheduleUpdate{TimeZone: "America/New_York", LocalTime: "08:30", ExpectedRevision: &revision}, "qa"); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 13, 29, 0, 0, time.UTC)
	a.dailyWorkerTick(ctx, at)
	if observations.Load() != 0 || a.dailyWorkerSnapshot(at).State != "waiting_schedule" {
		t.Fatal("report was generated before the local configured time")
	}
	at = at.Add(time.Minute)
	a.dailyWorkerTick(ctx, at)
	a.dailyWorkerTick(ctx, at.Add(time.Minute))
	if observations.Load() != 1 || a.dailyWorkerSnapshot(at.Add(time.Minute)).State != "saved" {
		t.Fatal("scheduled worker did not save once")
	}
	if _, report, err := readDailyReportRecord(ctx, a.Store.DB, "2026-11-12"); err != nil || report["created_at"] != "2026-11-12T13:30:00Z" {
		t.Fatalf("unexpected saved report: %+v, %v", report, err)
	}
	var count int
	if err := a.Store.DB.QueryRow(`SELECT count(*) FROM notifications WHERE source='daily-report'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unexpected notification rows: %d, %v", count, err)
	}
}
