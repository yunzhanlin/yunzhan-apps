package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dailyWorkerFixture(t *testing.T, rows []SoftwareAppStatus, overviewError bool) (*Server, *atomic.Int32) {
	t.Helper()
	a, err := NewServer(testStore(t), Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	reads := &atomic.Int32{}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 11*time.Second {
			t.Fatal("background read lacks its finite child context")
		}
		var value any
		switch r.URL.Path {
		case "/v1/software":
			if r.Method != "GET" {
				t.Fatal("worker installation mutation")
			}
			value = rows
		case "/v1/overview":
			reads.Add(1)
			if overviewError {
				return nil, errors.New("private-diagnostic-not-exported")
			}
			value = map[string]any{"cpu_percent": nil, "cpu_available": false, "memory_percent": 0, "memory_available": true, "disk_available": 4096, "disk_percent": 50, "disk_percent_available": true}
		case "/v1/sites/traffic":
			if r.Method != "POST" {
				t.Fatal("traffic read method")
			}
			value = map[string]any{"days": []any{}, "sites": []any{}, "partial": false}
		default:
			t.Fatal("worker escaped its read-only fixed executor endpoints", r.URL.Path)
		}
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	})}}
	return a, reads
}

func dailyWorkerInstalled() []SoftwareAppStatus {
	return []SoftwareAppStatus{{ID: "daily-report", Installed: true, Enabled: true, Healthy: true, Version: "1.4.0"}}
}

func TestDailyWorkerSavesOnceAndUsesOneCalendarObservation(t *testing.T) {
	a, reads := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	at := time.Date(2026, 10, 11, 16, 30, 0, 0, time.UTC)
	a.dailyWorkerTick(context.Background(), at)
	day, report, err := readDailyReportRecord(context.Background(), a.Store.DB, "2026-10-12")
	if err != nil || day != "2026-10-12" || report["created_at"] != "2026-10-11T16:30:00Z" {
		t.Fatal("one captured date was not used throughout", day, report, err)
	}
	a.dailyWorkerTick(context.Background(), at.Add(time.Minute))
	var reports, events int
	a.Store.DB.QueryRow(`SELECT count(*) FROM app_daily_reports`).Scan(&reports)
	a.Store.DB.QueryRow(`SELECT count(*) FROM notifications WHERE source='daily-report'`).Scan(&events)
	state := a.dailyWorkerSnapshot(at.Add(time.Minute))
	if reads.Load() != 1 || reports != 1 || events != 1 || state.State != "saved" || state.ReportDay != day || !state.Fresh || state.Running {
		t.Fatal("existing valid daily report regenerated or tick falsely claimed live goroutine", reads.Load(), state)
	}
}

func TestDailyWorkerUnknownDisabledDuplicateAndUnhealthyNeverGenerate(t *testing.T) {
	good := dailyWorkerInstalled()[0]
	for name, rows := range map[string][]SoftwareAppStatus{"missing": {}, "duplicate": {good, good}, "unknown": {{ID: good.ID, Installed: true, Enabled: true, Healthy: true, StateUnknown: true}}, "disabled": {{ID: good.ID, Installed: true, Healthy: true}}, "unhealthy": {{ID: good.ID, Installed: true, Enabled: true}}, "uninstalled": {{ID: good.ID}}} {
		t.Run(name, func(t *testing.T) {
			a, reads := dailyWorkerFixture(t, rows, false)
			at := time.Now()
			a.dailyWorkerTick(context.Background(), at)
			var reports int
			a.Store.DB.QueryRow(`SELECT count(*) FROM app_daily_reports`).Scan(&reports)
			state := a.dailyWorkerSnapshot(at)
			if reads.Load() != 0 || reports != 0 || state.State == "saved" || state.Error == "" {
				t.Fatal("unknown/inactive application generated a report", state)
			}
		})
	}
}

func TestDailyWorkerDamagedRecordRemainsBlockedAndUnchanged(t *testing.T) {
	a, reads := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	at := time.Now()
	day := at.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02")
	raw := `{"sites":-1}`
	if _, err := a.Store.DB.Exec(`INSERT INTO app_daily_reports VALUES(?,?,?)`, day, raw, Now()); err != nil {
		t.Fatal(err)
	}
	a.dailyWorkerTick(context.Background(), at)
	var retained string
	a.Store.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&retained)
	if retained != raw || reads.Load() != 0 || a.dailyWorkerSnapshot(at).State != "blocked_original" {
		t.Fatal("background repaired or overwrote original")
	}
}

func TestDailyWorkerGenerationFailureIsVisibleAndDoesNotSave(t *testing.T) {
	a, reads := dailyWorkerFixture(t, dailyWorkerInstalled(), true)
	at := time.Now()
	a.dailyWorkerTick(context.Background(), at)
	state := a.dailyWorkerSnapshot(at)
	var n int
	a.Store.DB.QueryRow(`SELECT count(*) FROM app_daily_reports`).Scan(&n)
	if reads.Load() != 1 || n != 0 || state.State != "generation_failed" || state.Error == "" || strings.Contains(state.Error, "private-diagnostic") {
		t.Fatal("failed source became a saved report or disclosed raw error", state)
	}
	if a.dailyWorkerSnapshot(at.Add(131*time.Second)).Fresh || a.dailyWorkerSnapshot(at.Add(-time.Second)).Fresh {
		t.Fatal("old or future observation claimed fresh")
	}
}

func TestDailyWorkerStartIsSingleAndCancellationClearsLiveState(t *testing.T) {
	a, _ := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	var requests atomic.Int32
	entered := make(chan struct{}, 1)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		entered <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartAppDailyWorker(ctx)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	a.StartAppDailyWorker(ctx)
	if requests.Load() != 1 || !a.dailyWorkerSnapshot(time.Now()).Running {
		t.Fatal("duplicate worker or false stopped state")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for a.dailyWorkerSnapshot(time.Now()).Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	state := a.dailyWorkerSnapshot(time.Now())
	if state.Running || state.State != "stopped" || state.NextCheckAt != "" {
		t.Fatal("stopped worker still claims active schedule", state)
	}
}
