package core

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// This is observed process-local worker state, not SMTP delivery or a persisted
// heartbeat surviving process death. A new server starts explicitly unknown.
type DailyWorkerStatus struct {
	Running     bool   `json:"running"`
	State       string `json:"state"`
	CheckedAt   string `json:"checked_at,omitempty"`
	NextCheckAt string `json:"next_check_at,omitempty"`
	ReportDay   string `json:"report_day,omitempty"`
	Error       string `json:"error,omitempty"`
	Fresh       bool   `json:"fresh"`
}

func (a *Server) dailyWorkerSnapshot(now time.Time) DailyWorkerStatus {
	a.dailyWorkerMu.Lock()
	v := a.dailyWorkerStatus
	v.Running = a.dailyWorkerStarted
	a.dailyWorkerMu.Unlock()
	if v.State == "" {
		v.State = "unknown"
	}
	checked, err := time.Parse(time.RFC3339, v.CheckedAt)
	v.Fresh = err == nil && !now.Before(checked) && now.Sub(checked) <= 130*time.Second
	return v
}

func (a *Server) dailyWorkerObserved(at time.Time, state, day, message string) {
	a.dailyWorkerMu.Lock()
	a.dailyWorkerStatus = DailyWorkerStatus{State: state, CheckedAt: at.UTC().Format(time.RFC3339), NextCheckAt: at.Add(time.Minute).UTC().Format(time.RFC3339), ReportDay: day, Error: message}
	a.dailyWorkerMu.Unlock()
}

func (a *Server) dailyWorkerTick(parent context.Context, at time.Time) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return
	}
	var rows []SoftwareAppStatus
	if err := a.Executor.Call(ctx, "GET", "/v1/software", nil, &rows); err != nil || len(rows) > 128 {
		a.dailyWorkerObserved(at, "status_unknown", "", "应用安装状态读取失败；未生成或覆盖日报")
		return
	}
	var status SoftwareAppStatus
	count := 0
	for _, row := range rows {
		if row.ID == "daily-report" {
			status = row
			count++
		}
	}
	if count != 1 || status.StateUnknown {
		a.dailyWorkerObserved(at, "status_unknown", "", "应用身份缺失、重复或待核对；未生成日报")
		return
	}
	if !status.Installed || !status.Enabled {
		a.dailyWorkerObserved(at, "inactive", "", "应用未安装或未启用；后台不生成日报")
		return
	}
	if !status.Healthy {
		a.dailyWorkerObserved(at, "status_unknown", "", "应用运行状态无法核对；未生成日报")
		return
	}
	day := at.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02")
	_, report, err := readDailyReportRecord(ctx, a.Store.DB, day)
	if err == nil {
		a.dailyWorkerSaved(at, day, report)
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		a.dailyWorkerObserved(at, "blocked_original", day, "今日原日报无法核对；保留原记录，未重新生成或覆盖")
		return
	}
	generated, err := a.appDailyReportAt(ctx, at)
	if err != nil {
		a.dailyWorkerObserved(at, "generation_failed", day, "资源、业务记录或原子保存失败；没有据此认定日报已生成")
		return
	}
	a.dailyWorkerSaved(at, day, generated.(map[string]any))
}

func (a *Server) dailyWorkerSaved(at time.Time, day string, report map[string]any) {
	for _, key := range []string{"traffic_error", "security_error", "certificates_error"} {
		if message, ok := report[key].(string); ok && message != "" {
			a.dailyWorkerObserved(at, "saved_partial", day, "日报已保存，但部分来源采集失败；查看保存报告，不能据此认定全量采集正常")
			return
		}
	}
	a.dailyWorkerObserved(at, "saved", day, "")
}

func (a *Server) StartAppDailyWorker(ctx context.Context) {
	a.dailyWorkerMu.Lock()
	if a.dailyWorkerStarted || ctx.Err() != nil {
		a.dailyWorkerMu.Unlock()
		return
	}
	a.dailyWorkerStarted = true
	a.dailyWorkerStatus = DailyWorkerStatus{State: "starting"}
	a.dailyWorkerMu.Unlock()
	go func() {
		defer func() {
			a.dailyWorkerMu.Lock()
			a.dailyWorkerStarted = false
			a.dailyWorkerStatus.State = "stopped"
			a.dailyWorkerStatus.NextCheckAt = ""
			a.dailyWorkerMu.Unlock()
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		a.dailyWorkerTick(ctx, time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-ticker.C:
				a.dailyWorkerTick(ctx, at)
			}
		}
	}()
}
