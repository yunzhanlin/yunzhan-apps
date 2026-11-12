package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
)

const maxDailyReportScheduleRevision = 1<<53 - 1

var dailyReportZonePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+/-]{0,79}$`)
var errDailyReportScheduleChanged = errors.New("日报生成时间已变化，请刷新后重试")

type dailyReportSchedule struct {
	TimeZone  string `json:"time_zone"`
	LocalTime string `json:"local_time"`
	Revision  int64  `json:"revision"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type dailyReportScheduleUpdate struct {
	TimeZone         string `json:"time_zone"`
	LocalTime        string `json:"local_time"`
	ExpectedRevision *int64 `json:"expected_revision"`
}

type dailyReportScheduleReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func defaultDailyReportSchedule() dailyReportSchedule {
	return dailyReportSchedule{TimeZone: "Asia/Shanghai", LocalTime: "00:00"}
}

func (s dailyReportSchedule) location() (*time.Location, error) {
	if !dailyReportZonePattern.MatchString(s.TimeZone) || strings.Contains(s.TimeZone, "//") ||
		s.TimeZone == "Local" || strings.HasSuffix(s.TimeZone, "/") {
		return nil, errors.New("请输入有效的 IANA 时区，如 Asia/Shanghai 或 UTC")
	}
	location, err := time.LoadLocation(s.TimeZone)
	if err != nil {
		return nil, errors.New("当前系统无法读取所选时区")
	}
	clock, err := time.Parse("15:04", s.LocalTime)
	if err != nil || clock.Format("15:04") != s.LocalTime {
		return nil, errors.New("日报时间应为 HH:MM")
	}
	return location, nil
}

func readDailyReportSchedule(ctx context.Context, db dailyReportScheduleReader) (dailyReportSchedule, error) {
	var schedule dailyReportSchedule
	err := db.QueryRowContext(ctx, `SELECT time_zone,local_time,revision,updated_at
		FROM app_daily_report_schedule WHERE singleton=1`).Scan(&schedule.TimeZone, &schedule.LocalTime, &schedule.Revision, &schedule.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultDailyReportSchedule(), nil
	}
	if _, stampErr := time.Parse(time.RFC3339, schedule.UpdatedAt); err != nil || stampErr != nil ||
		schedule.Revision <= 0 || schedule.Revision > maxDailyReportScheduleRevision {
		return dailyReportSchedule{}, errors.New("无法核对已保存的日报时间")
	}
	if _, err := schedule.location(); err != nil {
		return dailyReportSchedule{}, err
	}
	return schedule, nil
}

func (s *Store) updateDailyReportSchedule(ctx context.Context, input dailyReportScheduleUpdate, actor string) (dailyReportSchedule, error) {
	next := dailyReportSchedule{TimeZone: input.TimeZone, LocalTime: input.LocalTime}
	if _, err := next.location(); err != nil {
		return next, err
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 0 || *input.ExpectedRevision >= maxDailyReportScheduleRevision {
		return next, errors.New("请先读取当前日报时间的修订号")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return next, err
	}
	defer tx.Rollback()
	old, err := readDailyReportSchedule(ctx, tx)
	if err != nil {
		return next, err
	}
	if old.Revision != *input.ExpectedRevision {
		return next, errDailyReportScheduleChanged
	}
	if old.TimeZone == next.TimeZone && old.LocalTime == next.LocalTime {
		return old, nil
	}
	next.Revision, next.UpdatedAt = old.Revision+1, Now()
	result, err := tx.ExecContext(ctx, `INSERT INTO app_daily_report_schedule(singleton,time_zone,local_time,revision,updated_at)
		VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET
		time_zone=excluded.time_zone,local_time=excluded.local_time,revision=excluded.revision,updated_at=excluded.updated_at
		WHERE app_daily_report_schedule.revision=?`, next.TimeZone, next.LocalTime, next.Revision, next.UpdatedAt, old.Revision)
	if err != nil {
		return next, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return next, errDailyReportScheduleChanged
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at)
		VALUES(?,'daily-report.schedule','daily-report','updated',?)`, actor, next.UpdatedAt); err != nil {
		return next, err
	}
	return next, tx.Commit()
}

func (a *Server) configuredDailyReportNow(ctx context.Context, at time.Time) (any, error) {
	schedule, err := readDailyReportSchedule(ctx, a.Store.DB)
	if err != nil {
		return nil, err
	}
	location, err := schedule.location()
	if err != nil {
		return nil, err
	}
	return a.appDailyReportForDay(ctx, at, at.In(location).Format("2006-01-02"), &schedule.Revision, false)
}

func (a *Server) dailyReportScheduleRoutes(m *http.ServeMux) {
	const route = "/api/app-modules/daily-report/schedule"
	installed := func(w http.ResponseWriter, r *http.Request) bool {
		var module struct {
			Status SoftwareAppStatus `json:"status"`
		}
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/app-modules/daily-report", nil, &module); err != nil ||
			!knownInstalledAppModule("daily-report", module.Status) || module.Status.Version != appcatalog.DailyReportScheduleVersion {
			fail(w, http.StatusConflict, "请先签名安装或更新支持日报生成时间的应用")
			return false
		}
		return true
	}
	m.HandleFunc("GET "+route, a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		if !installed(w, r) {
			return
		}
		schedule, err := readDailyReportSchedule(r.Context(), a.Store.DB)
		if err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		send(w, http.StatusOK, schedule)
	}))
	m.HandleFunc("POST "+route, a.authorize(func(w http.ResponseWriter, r *http.Request, user identity) {
		if !installed(w, r) {
			return
		}
		var input dailyReportScheduleUpdate
		if !decode(w, r, &input) {
			return
		}
		schedule, err := a.Store.updateDailyReportSchedule(r.Context(), input, user.Username)
		if err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		send(w, http.StatusOK, schedule)
	}))
}
