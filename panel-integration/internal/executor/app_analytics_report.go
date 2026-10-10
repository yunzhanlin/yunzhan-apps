package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type analyticsAccess struct {
	Time, Remote, Method, Path, Agent, Referer string
	Status                                     int
	Bytes                                      int64
	Seconds                                    float64
}

type analyticsVisitor struct {
	IP       string  `json:"ip"`
	Requests int     `json:"requests"`
	Bytes    int64   `json:"bytes"`
	Errors   int     `json:"errors"`
	Seconds  float64 `json:"total_seconds"`
}

func analyticsWindow(in core.AppModuleInput) (time.Time, time.Time, error) {
	var from, to time.Time
	var err error
	if in.FromTime != "" {
		from, err = time.Parse(time.RFC3339, in.FromTime)
		if err != nil {
			return from, to, errors.New("开始时间必须是 RFC3339 格式")
		}
	}
	if in.ToTime != "" {
		to, err = time.Parse(time.RFC3339, in.ToTime)
		if err != nil {
			return from, to, errors.New("结束时间必须是 RFC3339 格式")
		}
	}
	if !from.IsZero() && !to.IsZero() && !to.After(from) {
		return from, to, errors.New("结束时间必须晚于开始时间")
	}
	if len(in.Search) > 256 || in.StatusCode != 0 && (in.StatusCode < 100 || in.StatusCode > 599) || math.IsNaN(in.MinSeconds) || math.IsInf(in.MinSeconds, 0) || in.MinSeconds < 0 || in.MinSeconds > 3600 {
		return from, to, errors.New("统计筛选参数无效")
	}
	return from, to, nil
}

func analyticsClient(agent string) (browser, device string, bot bool) {
	agent = strings.ToLower(agent)
	bot = strings.Contains(agent, "bot") || strings.Contains(agent, "crawler") || strings.Contains(agent, "spider") || strings.Contains(agent, "bingpreview")
	switch {
	case bot:
		browser = "Crawler"
	case strings.Contains(agent, "edg/"):
		browser = "Edge"
	case strings.Contains(agent, "firefox/"):
		browser = "Firefox"
	case strings.Contains(agent, "chrome/") || strings.Contains(agent, "crios/"):
		browser = "Chrome"
	case strings.Contains(agent, "safari/"):
		browser = "Safari"
	case strings.Contains(agent, "curl/"):
		browser = "curl"
	default:
		browser = "Other"
	}
	switch {
	case bot:
		device = "Crawler"
	case strings.Contains(agent, "ipad") || strings.Contains(agent, "tablet"):
		device = "Tablet"
	case strings.Contains(agent, "mobile") || strings.Contains(agent, "iphone") || strings.Contains(agent, "android"):
		device = "Mobile"
	default:
		device = "Desktop / Other"
	}
	return
}

func analyticsReferer(value string) string {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Bounds apply to both log bytes and cardinality: report generation remains
// usable on small servers, and returns explicit partial-result indicators.
func buildAnalyticsReport(ctx context.Context, reader io.Reader, id string, in core.AppModuleInput, partial bool, now time.Time) (map[string]any, error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 16<<20))
	scanner.Buffer(make([]byte, 4096), 65536)
	return buildAnalyticsRows(ctx, func() (analyticsAccess, error) {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return analyticsAccess{}, err
			}
			return analyticsAccess{}, io.EOF
		}
		var row analyticsAccess
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			return analyticsAccess{}, nil
		}
		return row, nil
	}, id, in, partial, now)
}

// The durable history reader is bounded by its database row/page budgets, not
// the legacy 16 MiB tail limit. Both sources use the same report accumulator.
func buildAnalyticsRows(ctx context.Context, next func() (analyticsAccess, error), id string, in core.AppModuleInput, partial bool, now time.Time) (map[string]any, error) {
	from, to, err := analyticsWindow(in)
	if err != nil {
		return nil, err
	}
	slowThreshold := in.MinSeconds
	if slowThreshold == 0 {
		slowThreshold = 1
	}
	paths, codes, hours, referers, browsers, devices, methods, spiders := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	ips := map[string]bool{}
	visitors := map[string]*analyticsVisitor{}
	cardinalityLimited := false
	keyBudget := 200 << 10
	count := func(m map[string]int, k string) {
		if _, ok := m[k]; !ok {
			cost := 6*len(k) + 16 // Includes worst-case JSON string escaping.
			if len(k) > 512 || len(m) >= 1000 || cost > keyBudget {
				cardinalityLimited = true
				return
			}
			keyBudget -= cost
		}
		m[k]++
	}
	requests, errorsCount, bots, invalid, recent, slowCount := 0, 0, 0, 0, 0, 0
	var transferred int64
	var seconds, maxSeconds float64
	latency := analyticsLatencyAccumulator{}
	errorRows, slowRows := []map[string]any{}, []map[string]any{}
	appendSample := func(rows []map[string]any, row map[string]any) []map[string]any {
		if len(rows) == 100 {
			copy(rows, rows[1:])
			rows[99] = row
			return rows
		}
		return append(rows, row)
	}
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		row, readErr := next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if row.Status < 100 || row.Status > 599 || row.Bytes < 0 || row.Bytes > 1<<40 || math.IsNaN(row.Seconds) || math.IsInf(row.Seconds, 0) || row.Seconds < 0 || row.Seconds > 86400 || len(row.Path) > 8192 || len(row.Method) > 32 || row.Remote != "" && net.ParseIP(row.Remote) == nil {
			invalid++
			continue
		}
		ts, te := time.Parse(time.RFC3339, row.Time)
		if te != nil {
			invalid++
			continue
		}
		if !from.IsZero() && ts.Before(from) || !to.IsZero() && !ts.Before(to) {
			continue
		}
		row.Path, _, _ = strings.Cut(row.Path, "?")
		row.Referer = analyticsReferer(row.Referer)
		browser, device, bot := analyticsClient(row.Agent)
		if in.OnlyBots && !bot || in.StatusCode != 0 && row.Status != in.StatusCode || in.Search != "" && !strings.Contains(row.Path, in.Search) && !strings.Contains(row.Remote, in.Search) {
			continue
		}
		requests++
		latency.add(row.Seconds)
		transferred += row.Bytes
		seconds += row.Seconds
		maxSeconds = max(maxSeconds, row.Seconds)
		count(paths, row.Path)
		count(codes, strconv.Itoa(row.Status))
		count(hours, ts.UTC().Format("2006-01-02T15:00Z"))
		count(browsers, browser)
		count(devices, device)
		count(methods, row.Method)
		if row.Referer != "" {
			count(referers, row.Referer)
		}
		if bot {
			bots++
			name := strings.Split(row.Agent, "/")[0]
			if len(name) > 128 {
				name = name[:128]
			}
			count(spiders, name)
		}
		if !ts.Before(now.Add(-time.Minute)) && !ts.After(now) {
			recent++
		}
		if row.Remote != "" {
			if len(ips) < 50000 || ips[row.Remote] {
				ips[row.Remote] = true
			} else {
				cardinalityLimited = true
			}
			v := visitors[row.Remote]
			if v == nil && len(visitors) < 5000 {
				v = &analyticsVisitor{IP: row.Remote}
				visitors[row.Remote] = v
			}
			if v != nil {
				v.Requests++
				v.Bytes += row.Bytes
				v.Seconds += row.Seconds
				if row.Status >= 400 {
					v.Errors++
				}
			}
		}
		samplePath := row.Path
		if len(samplePath) > 256 {
			samplePath = samplePath[:256] + "…"
			cardinalityLimited = true
		}
		sample := map[string]any{"time": row.Time, "ip": row.Remote, "method": row.Method, "path": samplePath, "status": row.Status, "bytes": row.Bytes, "seconds": row.Seconds, "browser": browser, "device": device}
		if row.Status >= 400 {
			errorsCount++
			errorRows = appendSample(errorRows, sample)
		}
		if row.Seconds >= slowThreshold {
			slowCount++
			slowRows = appendSample(slowRows, sample)
		}
	}
	visitorRows := make([]analyticsVisitor, 0, len(visitors))
	for _, v := range visitors {
		visitorRows = append(visitorRows, *v)
	}
	sort.Slice(visitorRows, func(i, j int) bool {
		if visitorRows[i].Requests == visitorRows[j].Requests {
			return visitorRows[i].IP < visitorRows[j].IP
		}
		return visitorRows[i].Requests > visitorRows[j].Requests
	})
	if len(visitorRows) > 100 {
		visitorRows = visitorRows[:100]
	}
	average := float64(0)
	if requests > 0 {
		average = seconds / float64(requests)
	}
	filters := map[string]any{"from_time": in.FromTime, "to_time": in.ToTime, "search": in.Search, "status_code": in.StatusCode, "min_seconds": in.MinSeconds, "only_bots": in.OnlyBots}
	latencyReport, err := latency.report(ctx, partial || cardinalityLimited)
	if err != nil {
		return nil, err
	}
	return map[string]any{"site_id": id, "requests": requests, "bytes": transferred, "unique_ips": len(ips), "errors": errorsCount, "bots": bots, "paths": paths, "status_codes": codes, "hours": hours, "referers": referers, "total_seconds": seconds, "average_seconds": average, "max_seconds": maxSeconds, "latency": latencyReport, "qps_last_minute": float64(recent) / 60, "browsers": browsers, "devices": devices, "methods": methods, "spiders": spiders, "visitors": visitorRows, "error_requests": errorRows, "slow_requests": slowRows, "slow_count": slowCount, "slow_threshold_seconds": slowThreshold, "invalid_lines": invalid, "cardinality_limited": cardinalityLimited, "partial": partial || cardinalityLimited, "updated_at": now.UTC().Format(time.RFC3339), "filters": filters, "scope": "最后 16 MiB 网站访问日志；时间为 UTC；独立 IP 不等于 UV；错误和慢请求各保留最近 100 条"}, nil
}
