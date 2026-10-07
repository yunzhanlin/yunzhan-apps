package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type analyticsFunnelStep struct {
	Path         string  `json:"path"`
	Sessions     int     `json:"sessions"`
	OverallRate  float64 `json:"overall_rate"`
	PreviousRate float64 `json:"previous_rate"`
	DropOff      int     `json:"drop_off"`
}

type analyticsFunnelReport struct {
	Source            string                `json:"source"`
	From              string                `json:"from"`
	To                string                `json:"to"`
	WindowMinutes     int                   `json:"window_minutes"`
	SampledPageviews  int                   `json:"sampled_pageviews"`
	UniquePageviews   int                   `json:"unique_pageviews"`
	Partial           bool                  `json:"partial"`
	Steps             []analyticsFunnelStep `json:"steps"`
	CompletedSessions int                   `json:"completed_sessions"`
	Duration          map[string]float64    `json:"duration_seconds"`
	Limitations       []string              `json:"limitations"`
}

func analyticsWindow(rawFrom, rawTo string, now time.Time) (time.Time, time.Time, error) {
	from, to := now.UTC().Truncate(24*time.Hour), now.Add(time.Second)
	var err error
	if rawFrom != "" {
		from, err = time.Parse(time.RFC3339, rawFrom)
		if err != nil {
			return from, to, errors.New("开始时间无效")
		}
	}
	if rawTo != "" {
		to, err = time.Parse(time.RFC3339, rawTo)
		if err != nil {
			return from, to, errors.New("结束时间无效")
		}
	}
	if !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return from, to, errors.New("统计窗口须大于零且不超过 31 天")
	}
	return from.UTC(), to.UTC(), nil
}

func analyticsFunnelPaths(raw []string) ([]string, error) {
	if len(raw) < 2 || len(raw) > 8 {
		return nil, errors.New("漏斗需要 2–8 个顺序页面")
	}
	out := make([]string, len(raw))
	for i, value := range raw {
		parsed, err := url.Parse(value)
		if err != nil || strings.ContainsAny(value, "?#\\") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("漏斗页面只能使用不含查询、片段和反斜杠的本网站路径")
		}
		out[i], err = analyticsPath(value)
		if err != nil {
			return nil, err
		}
		// Apply the same URL escaping as collection, but never silently strip
		// private query strings or treat a full URL as a page match.
		if len(out[i]) > 2048 {
			return nil, errors.New("漏斗页面路径过长")
		}
	}
	return out, nil
}

func (a *Server) analyticsFunnel(w http.ResponseWriter, r *http.Request, u identity) {
	if _, err := a.Store.Site(r.PathValue("id")); err != nil {
		fail(w, 404, "网站不存在")
		return
	}
	query := r.URL.Query()
	minutes := 30
	if raw := query.Get("window_minutes"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1440 {
			fail(w, 400, "转化时限应为 1–1440 分钟")
			return
		}
		minutes = parsed
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := a.Store.analyticsFunnelReport(ctx, r.PathValue("id"), query["step"], query.Get("from"), query.Get("to"), minutes, time.Now())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	send(w, 200, out)
}

func (s *Store) analyticsFunnelReport(ctx context.Context, siteID string, rawSteps []string, rawFrom, rawTo string, minutes int, now time.Time) (analyticsFunnelReport, error) {
	out := analyticsFunnelReport{Source: "browser-telemetry", WindowMinutes: minutes, Steps: []analyticsFunnelStep{}, Duration: map[string]float64{}, Limitations: []string{
		"仅按本网站页面路径精确匹配；允许步骤之间浏览其他页面，重复步骤必须来自不同页面访问。",
		"按服务端接收时间排序，同秒按入库顺序；离线重发或网络乱序可能影响结果，浏览器事件不等于支付或业务审计。",
		"每个浏览器会话最多计数一次；可重新从入口尝试，转化时限从对应入口开始，已经达到的阶段不会因后续逾时撤销。",
		"只处理时间范围内最新 20000 条页面事件或 8 MiB 原始数据；截断、窗口边界与保留期可能丢失早期步骤，partial 为 true 时必须缩短范围。",
		"只返回聚合计数与耗时；不返回访客、会话、原始 IP、查询字符串或表单内容。",
	}}
	steps, err := analyticsFunnelPaths(rawSteps)
	if err != nil {
		return out, err
	}
	if minutes < 1 || minutes > 1440 {
		return out, errors.New("转化时限应为 1–1440 分钟")
	}
	from, to, err := analyticsWindow(rawFrom, rawTo, now)
	if err != nil {
		return out, err
	}
	out.From, out.To = from.Format(time.RFC3339), to.Format(time.RFC3339)
	rows, err := s.DB.QueryContext(ctx, `SELECT received,session,visitor,path,data FROM analytics_events WHERE site_id=? AND kind='pageview' AND received>=? AND received<? ORDER BY received DESC,rowid DESC LIMIT ?`, siteID, from.Unix(), to.Unix(), analyticsReportLimit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	events := []AnalyticsEvent{}
	bytes := 0
	for rows.Next() {
		var v AnalyticsEvent
		var raw string
		if err = rows.Scan(&v.Received, &v.Session, &v.Visitor, &v.Path, &raw); err != nil {
			return out, err
		}
		if len(events) == analyticsReportLimit || bytes+len(raw) > analyticsReportBytes {
			out.Partial = true
			break
		}
		bytes += len(raw)
		var data AnalyticsEvent
		if err = json.Unmarshal([]byte(raw), &data); err != nil {
			return out, errors.New("统计事件记录损坏")
		}
		// Ordering and scope come from server-written columns, not client time.
		v.PageID = data.PageID
		events = append(events, v)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	out.SampledPageviews = len(events)
	type progress struct {
		starts    []int64
		reached   int
		completed bool
	}
	sessions := map[string]*progress{}
	seen := map[string]bool{}
	durations := []float64{}
	window := int64(minutes) * 60
	for i := len(events) - 1; i >= 0; i-- {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		v := events[i]
		key := v.Visitor + ":" + v.Session
		page := key + ":" + v.PageID
		if seen[page] {
			continue
		}
		seen[page] = true
		out.UniquePageviews++
		ss := sessions[key]
		if ss == nil {
			ss = &progress{starts: make([]int64, len(steps))}
			for j := range ss.starts {
				ss.starts[j] = -1
			}
			sessions[key] = ss
		}
		if ss.completed {
			continue
		}
		// Descending traversal prevents a single pageview satisfying two
		// repeated steps. The latest viable entry dominates older entries for
		// each stage, allowing retries without quadratic attempt storage.
		for j := len(steps) - 1; j > 0; j-- {
			start := ss.starts[j-1]
			if v.Path == steps[j] && start >= 0 && v.Received >= start && v.Received-start <= window {
				ss.starts[j] = start
				if ss.reached < j+1 {
					ss.reached = j + 1
				}
				if j == len(steps)-1 {
					ss.completed = true
					durations = append(durations, float64(v.Received-start))
				}
			}
		}
		if v.Path == steps[0] {
			ss.starts[0] = v.Received
			if ss.reached == 0 {
				ss.reached = 1
			}
		}
	}
	counts := make([]int, len(steps))
	for _, ss := range sessions {
		for j := 0; j < ss.reached; j++ {
			counts[j]++
		}
	}
	for j, path := range steps {
		stage := analyticsFunnelStep{Path: path, Sessions: counts[j]}
		if counts[0] > 0 {
			stage.OverallRate = float64(counts[j]) * 100 / float64(counts[0])
		}
		if j == 0 {
			stage.PreviousRate = stage.OverallRate
		} else if counts[j-1] > 0 {
			stage.PreviousRate = float64(counts[j]) * 100 / float64(counts[j-1])
		}
		if j < len(steps)-1 {
			stage.DropOff = counts[j] - counts[j+1]
		}
		out.Steps = append(out.Steps, stage)
	}
	out.CompletedSessions = counts[len(steps)-1]
	if len(durations) > 0 {
		sort.Float64s(durations)
		var sum float64
		for _, value := range durations {
			sum += value
		}
		out.Duration["average"] = sum / float64(len(durations))
		for name, percent := range map[string]int{"p50": 50, "p75": 75, "p95": 95} {
			out.Duration[name] = durations[(len(durations)*percent+99)/100-1]
		}
	}
	return out, nil
}
