package core

import (
	"context"
	"errors"
	"net/http"
	"time"

	"local/panel/internal/appcatalog"
)

const AnalyticsPeriodComparisonAppVersion = "2.4.3"

func analyticsPeriodComparisonSupported(version string) bool {
	return version == AnalyticsPeriodComparisonAppVersion || version == AnalyticsLayoutHeatmapAppVersion || version == appcatalog.AnalyticsGeographyVersion
}

type analyticsComparisonPeriod struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	PV     int       `json:"pv"`
	UV     int       `json:"uv"`
	Visits int       `json:"sessions"`
	Clicks int       `json:"clicks"`
}

type analyticsComparison struct {
	SiteID          string                    `json:"site_id"`
	Current         analyticsComparisonPeriod `json:"current"`
	Previous        analyticsComparisonPeriod `json:"previous"`
	RetentionDays   int                       `json:"retention_days"`
	WithinRetention bool                      `json:"within_retention"`
}

func (s *Store) analyticsCompare(ctx context.Context, id, rawFrom, rawTo string, now time.Time) (analyticsComparison, error) {
	result := analyticsComparison{SiteID: id}
	from, to, err := analyticsWindow(rawFrom, rawTo, now)
	if err != nil {
		return result, err
	}
	now = now.UTC().Truncate(time.Second)
	if rawFrom == "" || rawTo == "" || from.Nanosecond() != 0 || to.Nanosecond() != 0 || to.After(now.Add(time.Second)) {
		return result, errors.New("请选择精确到秒且已结束的统计窗口")
	}
	previous := from.Add(-to.Sub(from))
	result.Previous.From, result.Previous.To = previous, from
	result.Current.From, result.Current.To = from, to

	// Use the same pageview-based visitor and session definitions as the
	// overview. Both half-open windows use one SQLite snapshot, and count
	// retained rows without constructing the sampled detail reports.
	rows, err := s.DB.QueryContext(ctx, `
		WITH periods (period, start, finish) AS (VALUES (0, ?, ?), (1, ?, ?))
		SELECT p.period,
		       COUNT(*) FILTER (WHERE e.kind = 'pageview'),
		       COUNT(DISTINCT e.visitor) FILTER (WHERE e.kind = 'pageview'),
		       COUNT(DISTINCT e.session) FILTER (WHERE e.kind = 'pageview'),
		       COUNT(*) FILTER (WHERE e.kind = 'click'),
		       COALESCE((SELECT retention FROM analytics_config WHERE site_id = ?), 30)
		FROM periods p LEFT JOIN analytics_events e
		     ON e.site_id = ? AND e.received >= p.start AND e.received < p.finish
		     AND e.kind IN ('pageview', 'click')
		GROUP BY p.period ORDER BY p.period`,
		previous.Unix(), from.Unix(), from.Unix(), to.Unix(), id, id)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for index, period := range []*analyticsComparisonPeriod{&result.Previous, &result.Current} {
		var position int
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return result, err
			}
			return result, errors.New("统计周期读取不完整")
		}
		if err := rows.Scan(&position, &period.PV, &period.UV, &period.Visits, &period.Clicks, &result.RetentionDays); err != nil {
			return result, err
		}
		if position != index {
			return result, errors.New("统计周期顺序无法核对")
		}
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if result.RetentionDays < 1 || result.RetentionDays > 90 {
		return result, errors.New("统计数据保留期限无法核对")
	}
	result.WithinRetention = !previous.Before(now.Add(-time.Duration(result.RetentionDays) * 24 * time.Hour))
	return result, nil
}

func (a *Server) analyticsComparePeriods(w http.ResponseWriter, r *http.Request, _ identity) {
	id := r.PathValue("id")
	if _, err := a.Store.Site(id); err != nil {
		fail(w, http.StatusNotFound, "网站不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var module struct {
		Status SoftwareAppStatus `json:"status"`
	}
	if err := a.Executor.Call(ctx, "GET", "/v1/app-modules/website-analytics", nil, &module); err != nil ||
		!knownInstalledAppModule("website-analytics", module.Status) || !analyticsPeriodComparisonSupported(module.Status.Version) {
		fail(w, http.StatusConflict, "请通过签名应用商店更新网站分析后再比较统计周期")
		return
	}
	query := r.URL.Query()
	out, err := a.Store.analyticsCompare(ctx, id, query.Get("from"), query.Get("to"), time.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	send(w, http.StatusOK, out)
}
