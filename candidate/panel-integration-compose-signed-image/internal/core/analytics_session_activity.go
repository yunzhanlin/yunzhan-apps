package core

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
)

const analyticsSessionActivityLimit = 300
const analyticsSessionActivityBytes = 512 << 10

type analyticsSessionActivityEvent struct {
	Kind     string   `json:"kind"`
	Path     string   `json:"path"`
	Received int64    `json:"received_at"`
	Duration *float64 `json:"duration_seconds,omitempty"`
	X        *float64 `json:"x,omitempty"`
	Y        *float64 `json:"y,omitempty"`
}

type analyticsSessionActivity struct {
	SessionID string                          `json:"session_id"`
	From      string                          `json:"from"`
	To        string                          `json:"to"`
	Partial   bool                            `json:"partial"`
	Events    []analyticsSessionActivityEvent `json:"events"`
}

func (a *Server) analyticsSessionActivity(w http.ResponseWriter, r *http.Request, _ identity) {
	w.Header().Set("Cache-Control", "private, no-store")
	site, session := r.PathValue("id"), r.PathValue("session")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !ValidID(site) || !validAnalyticsActivityHash(session) || !validAnalyticsActivityHash(q.Get("visitor")) {
		fail(w, 400, "会话标识或查询参数无效")
		return
	}
	for key, values := range q {
		if len(values) != 1 || (key != "visitor" && key != "from" && key != "to") {
			fail(w, 400, "会话回看参数无效")
			return
		}
	}
	if _, err := a.Store.Site(site); err != nil {
		fail(w, 404, "网站不存在")
		return
	}
	if !a.Store.analyticsHasReceipt(r.Context(), appcatalog.AnalyticsSessionActivityVersion) {
		fail(w, 409, "请先从签名应用商店更新到支持会话活动回看的网站分析版本")
		return
	}
	from, to, err := analyticsWindow(q.Get("from"), q.Get("to"), time.Now())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := a.Store.readAnalyticsSessionActivity(ctx, site, session, q.Get("visitor"), from, to)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "所选时间范围内没有该会话")
		return
	}
	if err != nil {
		fail(w, 503, "暂时无法核对原始会话活动")
		return
	}
	send(w, 200, out)
}

func (s *Store) readAnalyticsSessionActivity(ctx context.Context, site, session, visitor string, from, to time.Time) (analyticsSessionActivity, error) {
	out := analyticsSessionActivity{SessionID: session, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Events: []analyticsSessionActivityEvent{}}
	// The report's date and site scope remains authoritative. Read a bounded
	// newest tail in one SQLite snapshot; only pre-existing analytics signals
	// are admitted, never raw payload fields or identifiers of other visitors.
	rows, err := s.DB.QueryContext(ctx, `SELECT data,received,kind,path FROM analytics_events
		WHERE site_id=? AND session=? AND visitor=? AND received>=? AND received<?
		AND kind IN ('pageview','click','engagement')
		ORDER BY received DESC,rowid DESC LIMIT ?`, site, session, visitor, from.Unix(), to.Unix(), analyticsSessionActivityLimit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var total int
	for rows.Next() {
		var raw, kind, path string
		var received int64
		if err := rows.Scan(&raw, &received, &kind, &path); err != nil {
			return out, err
		}
		total += len(raw)
		if len(out.Events) == analyticsSessionActivityLimit || total > analyticsSessionActivityBytes {
			out.Partial = true
			break
		}
		var e AnalyticsEvent
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return out, err
		}
		if e.Session != session || e.Visitor != visitor || e.Received != received || e.Kind != kind || e.Path != path {
			return out, errors.New("inconsistent stored analytics session event")
		}
		clean, pathErr := analyticsPath(path)
		if pathErr != nil || clean != path {
			return out, errors.New("inconsistent stored analytics path")
		}
		event := analyticsSessionActivityEvent{Kind: kind, Path: path, Received: received}
		switch e.Kind {
		case "pageview":
		case "engagement":
			if !validAnalyticsActivityNumber(e.Duration, 30) {
				return out, errors.New("invalid stored engagement duration")
			}
			event.Duration = &e.Duration
		case "click":
			if !validAnalyticsActivityNumber(e.X, 100) || !validAnalyticsActivityNumber(e.Y, 100) {
				return out, errors.New("invalid stored click coordinates")
			}
			event.X, event.Y = &e.X, &e.Y
		default:
			return out, errors.New("unexpected stored analytics session event")
		}
		out.Events = append(out.Events, event)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Events) == 0 && !out.Partial {
		return out, sql.ErrNoRows
	}
	// Only server reception order applies across click/engagement/page events;
	// browser navigation sequence orders pageviews, never other event types.
	for i, j := 0, len(out.Events)-1; i < j; i, j = i+1, j-1 {
		out.Events[i], out.Events[j] = out.Events[j], out.Events[i]
	}
	return out, nil
}

func validAnalyticsActivityNumber(value, max float64) bool {
	return !math.IsNaN(value) && value >= 0 && value <= max
}

func validAnalyticsActivityHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
