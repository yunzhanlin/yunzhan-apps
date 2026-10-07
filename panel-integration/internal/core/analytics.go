package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Independently authored, opt-in browser analytics. Reference plugin source is
// not included or executed. Inputs remain untrusted even with a valid site key.
const analyticsCapacity = 200000
const analyticsReportLimit = 20000
const analyticsReportBytes = 8 << 20

//go:embed analytics_tracker.js
var analyticsTracker string

// Locally bundled standard build, never a third-party network script. Keep the
// complete upstream Apache-2.0 license in every delivered tracker response.
//
//go:embed analytics_vendor/web-vitals-6.2.3.iife.js
var analyticsWebVitals string

//go:embed analytics_vendor/LICENSE.web-vitals
var analyticsWebVitalsLicense string

type AnalyticsConfig struct {
	SiteID        string `json:"site_id"`
	Key           string `json:"key"`
	Enabled       bool   `json:"enabled"`
	Clicks        bool   `json:"clicks"`
	Retention     int    `json:"retention_days"`
	Revision      int64  `json:"revision"`
	ProxyEndpoint string `json:"proxy_endpoint,omitempty"`
}

type analyticsRate struct {
	Window int64
	Count  int
}

type AnalyticsEvent struct {
	ID             string  `json:"id"`
	PageID         string  `json:"page_id"`
	Visitor        string  `json:"visitor"`
	Session        string  `json:"session"`
	Kind           string  `json:"kind"`
	Path           string  `json:"path"`
	Title          string  `json:"title"`
	Referer        string  `json:"referer"`
	Campaign       string  `json:"campaign"`
	Duration       float64 `json:"duration"`
	X              float64 `json:"x"`
	Y              float64 `json:"y"`
	TTFB           float64 `json:"ttfb"`
	FCP            float64 `json:"fcp"`
	LCP            float64 `json:"lcp"`
	CLS            float64 `json:"cls"`
	CLSAvailable   bool    `json:"cls_available"`
	INP            float64 `json:"inp"`
	INPAvailable   bool    `json:"inp_available"`
	PerformanceSeq int     `json:"performance_seq"`
	Received       int64   `json:"received_at"`
	IPHash         string  `json:"-"`
	Browser        string  `json:"browser"`
	Device         string  `json:"device"`
}

func (s *Store) migrateAnalytics() error {
	_, e := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS analytics_config(site_id TEXT PRIMARY KEY REFERENCES sites(id),public_key TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL,clicks INTEGER NOT NULL,retention INTEGER NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS analytics_events(site_id TEXT NOT NULL REFERENCES sites(id),id TEXT NOT NULL,received INTEGER NOT NULL,visitor TEXT NOT NULL,session TEXT NOT NULL,kind TEXT NOT NULL,path TEXT NOT NULL,ip_hash TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(site_id,id));
CREATE INDEX IF NOT EXISTS analytics_event_time ON analytics_events(site_id,received);
CREATE INDEX IF NOT EXISTS analytics_event_retention ON analytics_events(received);
CREATE TABLE IF NOT EXISTS analytics_budget(id INTEGER PRIMARY KEY CHECK(id=1),events INTEGER NOT NULL);
INSERT OR IGNORE INTO analytics_budget SELECT 1,count(*) FROM analytics_events;
CREATE TRIGGER IF NOT EXISTS analytics_event_insert AFTER INSERT ON analytics_events BEGIN UPDATE analytics_budget SET events=events+1 WHERE id=1; END;
CREATE TRIGGER IF NOT EXISTS analytics_event_delete AFTER DELETE ON analytics_events BEGIN UPDATE analytics_budget SET events=events-1 WHERE id=1; END;`)
	return e
}

func (s *Store) analyticsConfig(id string) (AnalyticsConfig, error) {
	v := AnalyticsConfig{SiteID: id, Retention: 30}
	e := s.DB.QueryRow(`SELECT public_key,enabled,clicks,retention,revision FROM analytics_config WHERE site_id=?`, id).Scan(&v.Key, &v.Enabled, &v.Clicks, &v.Retention, &v.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	return v, e
}

func (s *Store) saveAnalyticsConfig(ctx context.Context, in AnalyticsConfig) (AnalyticsConfig, error) {
	if !ValidID(in.SiteID) || in.Retention < 1 || in.Retention > 90 || in.Revision < 0 {
		return in, errors.New("统计配置参数无效，保留天数为 1–90")
	}
	if _, e := s.Site(in.SiteID); e != nil {
		return in, errors.New("网站不存在")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return in, e
	}
	defer tx.Rollback()
	in, e = saveAnalyticsConfigTx(tx, in)
	if e != nil {
		return in, e
	}
	return in, tx.Commit()
}

func analyticsPath(raw string) (string, error) {
	if len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("页面路径无效")
	}
	u, e := url.Parse(raw)
	if e != nil || u.IsAbs() || u.Host != "" {
		return "", errors.New("页面路径无效")
	}
	return u.EscapedPath(), nil
}

func validateAnalyticsEvent(v *AnalyticsEvent, clicks bool) error {
	if !ValidID(v.ID) || !ValidID(v.PageID) || !ValidID(v.Visitor) || !ValidID(v.Session) {
		return errors.New("事件标识无效")
	}
	if v.Kind != "pageview" && v.Kind != "engagement" && v.Kind != "performance" && !(v.Kind == "click" && clicks) {
		return errors.New("事件类型无效")
	}
	p, e := analyticsPath(v.Path)
	if e != nil {
		return e
	}
	v.Path = p
	if len(v.Title) > 256 || len(v.Campaign) > 128 || strings.ContainsAny(v.Title+v.Campaign, "\r\n\x00") {
		return errors.New("事件文本过长或无效")
	}
	for _, n := range []float64{v.Duration, v.X, v.Y, v.TTFB, v.FCP, v.LCP, v.CLS, v.INP} {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
			return errors.New("事件数值无效")
		}
	}
	if v.Duration > 30 || v.X > 100 || v.Y > 100 || v.TTFB > 300000 || v.FCP > 300000 || v.LCP > 300000 || v.CLS > 100 || v.INP > 300000 || v.PerformanceSeq < 0 || v.PerformanceSeq > 240 {
		return errors.New("事件数值超出范围")
	}
	if v.Kind != "click" {
		v.X = 0
		v.Y = 0
	}
	if v.Kind != "performance" {
		v.TTFB = 0
		v.FCP = 0
		v.LCP = 0
		v.CLS = 0
		v.CLSAvailable = false
		v.INP = 0
		v.INPAvailable = false
		v.PerformanceSeq = 0
	} else if !v.INPAvailable {
		v.INP = 0
	}
	if v.Kind != "engagement" {
		v.Duration = 0
	}
	if v.Referer != "" {
		u, e := url.Parse(v.Referer)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(u.Host) > 253 {
			return errors.New("来源地址无效")
		}
		v.Referer = strings.ToLower(u.Hostname())
	}
	return nil
}

func analyticsOrigin(site Site, raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	for _, d := range append([]string{site.Domain}, site.Settings.Domains...) {
		if strings.EqualFold(u.Hostname(), strings.Split(d, ":")[0]) {
			return true
		}
	}
	return false
}

func (a *Server) analyticsAllowed(ip string, now time.Time) bool {
	a.analyticsRateMu.Lock()
	defer a.analyticsRateMu.Unlock()
	if a.analyticsRates == nil {
		a.analyticsRates = map[string]analyticsRate{}
	}
	second, minute := now.Unix(), now.Unix()/60
	if a.analyticsGlobal.Window != second {
		a.analyticsGlobal = analyticsRate{Window: second}
	}
	if a.analyticsGlobal.Count >= 100 {
		return false
	}
	for k, v := range a.analyticsRates {
		if v.Window != minute {
			delete(a.analyticsRates, k)
		}
	}
	key := Hash(ip)
	v := a.analyticsRates[key]
	if v.Window != minute {
		v = analyticsRate{Window: minute}
	}
	if v.Count >= 1200 || len(a.analyticsRates) >= 2048 && v.Count == 0 {
		return false
	}
	v.Count++
	a.analyticsRates[key] = v
	a.analyticsGlobal.Count++
	return true
}

func (a *Server) analyticsSite(r *http.Request) (Site, AnalyticsConfig, error) {
	id, key := r.URL.Query().Get("site"), r.URL.Query().Get("key")
	if !ValidID(id) || !ValidID(key) {
		return Site{}, AnalyticsConfig{}, errors.New("统计标识无效")
	}
	site, e := a.Store.Site(id)
	if e != nil {
		return site, AnalyticsConfig{}, e
	}
	c, e := a.Store.analyticsConfig(id)
	if e != nil || !c.Enabled || !hmac.Equal([]byte(c.Key), []byte(key)) {
		return site, c, errors.New("未开启统计")
	}
	return site, c, nil
}

func (a *Server) analyticsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/analytics/sites/{id}/config", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		site, e := a.Store.Site(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "网站不存在")
			return
		}
		v, e := a.Store.analyticsConfig(r.PathValue("id"))
		if e != nil {
			fail(w, 500, "读取统计配置失败")
			return
		}
		v.ProxyEndpoint = site.Settings.AnalyticsEndpoint
		send(w, 200, v)
	}))
	m.HandleFunc("POST /api/analytics/sites/{id}/config", a.authorize(a.configureAnalyticsProxy))
	m.HandleFunc("GET /api/analytics/sites/{id}/funnel", a.authorize(a.analyticsFunnel))
	m.HandleFunc("GET /api/analytics/sites/{id}/report", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "网站不存在")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, e := a.Store.analyticsReport(ctx, r.PathValue("id"), r.URL.Query().Get("from"), r.URL.Query().Get("to"), time.Now())
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /collect/analytics/tracker.js", func(w http.ResponseWriter, r *http.Request) {
		_, c, e := a.analyticsSite(r)
		if e != nil {
			http.Error(w, "Not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		cfg, _ := json.Marshal(map[string]any{"site": c.SiteID, "key": c.Key, "clicks": c.Clicks})
		_, _ = io.WriteString(w, "(()=>{if(navigator.doNotTrack===\"1\"||navigator.globalPrivacyControl===true)return;\n/*\n"+analyticsWebVitalsLicense+"\n*/\n"+analyticsWebVitals+"\nconst config="+string(cfg)+";\n"+analyticsTracker+"\n})();")
	})
	m.HandleFunc("POST /collect/analytics/event", a.collectAnalytics)
}

func analyticsClient(agent string) (string, string) {
	s := strings.ToLower(agent)
	browser, device := "Other", "Desktop"
	switch {
	case strings.Contains(s, "bot") || strings.Contains(s, "spider") || strings.Contains(s, "crawler"):
		return "Bot", "Bot"
	case strings.Contains(s, "edg/"):
		browser = "Edge"
	case strings.Contains(s, "firefox/"):
		browser = "Firefox"
	case strings.Contains(s, "chrome/") || strings.Contains(s, "crios/"):
		browser = "Chrome"
	case strings.Contains(s, "safari/"):
		browser = "Safari"
	}
	if strings.Contains(s, "ipad") || strings.Contains(s, "tablet") {
		device = "Tablet"
	} else if strings.Contains(s, "mobile") || strings.Contains(s, "iphone") || strings.Contains(s, "android") {
		device = "Mobile"
	}
	return browser, device
}

func (a *Server) collectAnalytics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("DNT") == "1" || r.Header.Get("Sec-GPC") == "1" {
		w.WriteHeader(204)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	// Never trust a client-provided forwarding header for rate limits or IP data.
	if !a.analyticsAllowed(ip, time.Now()) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "采集请求过于频繁")
		return
	}
	site, c, e := a.analyticsSite(r)
	if e != nil {
		fail(w, 404, "统计未启用")
		return
	}
	if !analyticsOrigin(site, r.Header.Get("Origin")) {
		fail(w, 403, "统计来源不匹配")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" && r.Header.Get("Content-Type") != "text/plain;charset=UTF-8" {
		fail(w, 415, "采集格式不受支持")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var v AnalyticsEvent
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "采集数据无效")
		return
	}
	if e = validateAnalyticsEvent(&v, c.Clicks); e != nil {
		fail(w, 400, e.Error())
		return
	}
	v.Received = time.Now().Unix()
	v.Browser, v.Device = analyticsClient(r.UserAgent())
	if v.Device == "Bot" {
		w.WriteHeader(204)
		return
	}
	// Pseudonymous IDs are site-scoped server-side; never retain the raw IP.
	digest := func(value string) string {
		h := hmac.New(sha256.New, a.accountSecretKey)
		_, _ = h.Write([]byte("analytics:" + site.ID + ":" + value))
		return hex.EncodeToString(h.Sum(nil))
	}
	v.Visitor = digest(v.Visitor)
	v.Session = digest(v.Session)
	v.IPHash = digest(ip)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if e = a.Store.storeAnalyticsEvent(ctx, site.ID, c.Retention, v); e != nil {
		fail(w, 503, "采集存储暂不可用或已达到容量上限")
		return
	}
	w.WriteHeader(204)
}

func (s *Store) storeAnalyticsEvent(ctx context.Context, id string, retention int, v AnalyticsEvent) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// Cleanup is bounded and retention is explicit. A full store rejects new data
	// rather than silently evicting arbitrary recent events.
	_, e = tx.ExecContext(ctx, `DELETE FROM analytics_events WHERE rowid IN (SELECT rowid FROM analytics_events WHERE received<? OR (site_id=? AND received<?) LIMIT 500)`, time.Now().Add(-90*24*time.Hour).Unix(), id, time.Now().Add(-time.Duration(retention)*24*time.Hour).Unix())
	if e != nil {
		return e
	}
	var duplicate int
	e = tx.QueryRowContext(ctx, `SELECT count(*) FROM analytics_events WHERE site_id=? AND id=?`, id, v.ID).Scan(&duplicate)
	if e != nil {
		return e
	}
	if duplicate > 0 {
		return tx.Commit()
	}
	var total int
	if e = tx.QueryRowContext(ctx, `SELECT events FROM analytics_budget WHERE id=1`).Scan(&total); e != nil {
		return e
	}
	if total >= analyticsCapacity {
		return errors.New("analytics capacity reached")
	}
	data, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?,?)`, id, v.ID, v.Received, v.Visitor, v.Session, v.Kind, v.Path, v.IPHash, string(data))
	if e != nil {
		return e
	}
	return tx.Commit()
}

// Retention is enforced even when no visitor sends another event. Cleanup is
// bounded so an expired dataset cannot monopolize the control-plane database.
func (s *Store) cleanupAnalytics(ctx context.Context, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM analytics_events WHERE rowid IN (SELECT e.rowid FROM analytics_events e JOIN analytics_config c ON c.site_id=e.site_id WHERE e.received < ? - c.retention*86400 ORDER BY e.received LIMIT 1000)`, now.Unix())
	return err
}

func (a *Server) StartAnalyticsMaintenance(ctx context.Context) {
	go func() {
		timer := time.NewTicker(time.Minute)
		defer timer.Stop()
		for {
			cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := a.Store.cleanupAnalytics(cleanupCtx, time.Now())
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Printf("analytics retention cleanup: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
}

type analyticsDimension struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func analyticsDimensions(counts map[string]int) []analyticsDimension {
	out := []analyticsDimension{}
	for name, count := range counts {
		out = append(out, analyticsDimension{name, count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

type analyticsSession struct {
	ID       string   `json:"id"`
	Visitor  string   `json:"visitor"`
	Entry    string   `json:"entry"`
	Exit     string   `json:"exit"`
	Source   string   `json:"source"`
	First    int64    `json:"first"`
	Last     int64    `json:"last"`
	Pages    int      `json:"pages"`
	Duration float64  `json:"duration"`
	Journey  []string `json:"journey"`
}

type analyticsHeatPoint struct {
	Path  string `json:"path"`
	X     int    `json:"x"`
	Y     int    `json:"y"`
	Count int    `json:"count"`
}

func (s *Store) analyticsReport(ctx context.Context, id, rawFrom, rawTo string, now time.Time) (map[string]any, error) {
	from, to, e := analyticsWindow(rawFrom, rawTo, now)
	if e != nil {
		return nil, e
	}
	rows, e := s.DB.QueryContext(ctx, `SELECT data,ip_hash FROM analytics_events WHERE site_id=? AND received>=? AND received<? ORDER BY received DESC,rowid DESC LIMIT ?`, id, from.Unix(), to.Unix(), analyticsReportLimit+1)
	if e != nil {
		return nil, e
	}
	events := []AnalyticsEvent{}
	reportBytes, byteLimited := 0, false
	for rows.Next() {
		var raw, ip string
		if e = rows.Scan(&raw, &ip); e != nil {
			rows.Close()
			return nil, e
		}
		if reportBytes+len(raw) > analyticsReportBytes {
			byteLimited = true
			break
		}
		reportBytes += len(raw)
		var v AnalyticsEvent
		if e = json.Unmarshal([]byte(raw), &v); e != nil {
			rows.Close()
			return nil, e
		}
		v.IPHash = ip
		events = append(events, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	partial := len(events) > analyticsReportLimit || byteLimited
	if partial {
		if len(events) > analyticsReportLimit {
			events = events[:analyticsReportLimit]
		}
	}
	pages, sources, browsers, devices, entries, exits, hours, campaigns := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	visitors, ips, active := map[string]bool{}, map[string]bool{}, map[string]bool{}
	sessions := map[string]*analyticsSession{}
	heat := map[analyticsHeatPoint]*analyticsHeatPoint{}
	// Multiple lifecycle beacons for one navigation are updates, not independent
	// performance samples. Keep the newest sample per visitor/page navigation.
	performance := []AnalyticsEvent{}
	performanceIndex := map[string]int{}
	for _, v := range events {
		key := v.Visitor + ":" + v.PageID
		if v.Kind != "performance" {
			continue
		}
		if index, exists := performanceIndex[key]; exists {
			// An earlier request may reach the server after the final beacon.
			// INP may decrease when long visits exclude outliers, so neither
			// max(value) nor arrival time identifies the final measurement.
			if v.PerformanceSeq > performance[index].PerformanceSeq {
				performance[index] = v
			}
		} else if len(performance) < 5000 {
			performanceIndex[key] = len(performance)
			performance = append(performance, v)
		}
	}
	pv, clicks := 0, 0
	for i := len(events) - 1; i >= 0; i-- {
		v := events[i]
		ss := sessions[v.Session]
		if ss == nil {
			ss = &analyticsSession{ID: v.Session, Visitor: v.Visitor, First: v.Received, Journey: []string{}}
			sessions[v.Session] = ss
		}
		ss.Last = v.Received
		switch v.Kind {
		case "pageview":
			pv++
			visitors[v.Visitor] = true
			ips[v.IPHash] = true
			pages[v.Path]++
			browsers[v.Browser]++
			devices[v.Device]++
			hours[time.Unix(v.Received, 0).UTC().Format("2006-01-02T15:00Z")]++
			source := v.Referer
			if source == "" {
				source = "Direct"
			}
			sources[source]++
			if v.Campaign != "" {
				campaigns[v.Campaign]++
			}
			if ss.Pages == 0 {
				ss.Entry = v.Path
				ss.Source = source
			}
			ss.Exit = v.Path
			ss.Pages++
			if len(ss.Journey) < 20 {
				ss.Journey = append(ss.Journey, v.Path)
			}
		case "engagement":
			ss.Duration += v.Duration
		case "click":
			clicks++
			x, y := int(math.Min(v.X, 99.999))/5*5, int(math.Min(v.Y, 99.999))/5*5
			key := analyticsHeatPoint{Path: v.Path, X: x, Y: y}
			point := heat[key]
			if point == nil && len(heat) < 2000 {
				point = &analyticsHeatPoint{Path: v.Path, X: x, Y: y}
				heat[key] = point
			}
			if point != nil {
				point.Count++
			}
		}
		if v.Received >= now.Add(-5*time.Minute).Unix() && v.Received <= now.Unix() {
			active[v.Visitor] = true
		}
	}
	ssRows := []*analyticsSession{}
	bounces := 0
	duration := float64(0)
	for _, ss := range sessions {
		if ss.Pages == 0 {
			continue
		}
		entries[ss.Entry]++
		exits[ss.Exit]++
		if ss.Pages == 1 && ss.Duration < 10 {
			bounces++
		}
		duration += ss.Duration
		ssRows = append(ssRows, ss)
	}
	sort.Slice(ssRows, func(i, j int) bool {
		if ssRows[i].Last == ssRows[j].Last {
			return ssRows[i].ID < ssRows[j].ID
		}
		return ssRows[i].Last > ssRows[j].Last
	})
	sessionCount := len(ssRows)
	if len(ssRows) > 100 {
		ssRows = ssRows[:100]
	}
	metric := func(fn func(AnalyticsEvent) float64, available func(AnalyticsEvent) bool) map[string]any {
		values := []float64{}
		for _, v := range performance {
			n := fn(v)
			if n > 0 || available != nil && available(v) {
				values = append(values, n)
			}
		}
		sort.Float64s(values)
		out := map[string]any{"samples": len(values)}
		if len(values) > 0 {
			out["p75"] = values[int(math.Ceil(float64(len(values))*.75))-1]
		}
		return out
	}
	heatRows := []*analyticsHeatPoint{}
	for _, point := range heat {
		heatRows = append(heatRows, point)
	}
	sort.Slice(heatRows, func(i, j int) bool {
		x, y := heatRows[i], heatRows[j]
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		if x.X != y.X {
			return x.X < y.X
		}
		return x.Y < y.Y
	})
	bounceRate, avgDuration := float64(0), float64(0)
	if sessionCount > 0 {
		bounceRate = float64(bounces) / float64(sessionCount) * 100
		avgDuration = duration / float64(sessionCount)
	}
	return map[string]any{"source": "browser-telemetry", "from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "sampled_events": len(events), "partial": partial, "capacity_events": analyticsCapacity, "overview": map[string]any{"pv": pv, "uv": len(visitors), "unique_network_peers": len(ips), "sessions": sessionCount, "active_visitors": len(active), "clicks": clicks, "bounce_rate": bounceRate, "avg_engagement_seconds": avgDuration}, "pages": analyticsDimensions(pages), "sources": analyticsDimensions(sources), "browsers": analyticsDimensions(browsers), "devices": analyticsDimensions(devices), "entry_pages": analyticsDimensions(entries), "exit_pages": analyticsDimensions(exits), "hours": analyticsDimensions(hours), "campaigns": analyticsDimensions(campaigns), "sessions": ssRows, "heatmap": heatRows, "performance": map[string]any{"ttfb": metric(func(v AnalyticsEvent) float64 { return v.TTFB }, nil), "fcp": metric(func(v AnalyticsEvent) float64 { return v.FCP }, nil), "lcp": metric(func(v AnalyticsEvent) float64 { return v.LCP }, nil), "cls": metric(func(v AnalyticsEvent) float64 { return v.CLS }, func(v AnalyticsEvent) bool { return v.CLSAvailable }), "inp": metric(func(v AnalyticsEvent) float64 { return v.INP }, func(v AnalyticsEvent) bool { return v.INPAvailable })}, "limitations": []string{"浏览器标识是伪匿名标识，不等于真实人数；清除存储会成为新访客。", "报告最多聚合最近 20000 条窗口内事件，截断时明确标记；会话跨窗口或截断会影响跳出和旅程。", "原始 IP 不保留；网络对端数量在反向代理后可能是代理数，不冒充访客 IP 数。", "点击热图只记录归一化坐标，不读取表单和页面内容；不包含会话录像或地理位置库。漏斗在独立页按页面路径计算，不作为支付或业务审计。", "性能按导航去重，最多采样最近 5000 次导航；INP 来自本地打包 web-vitals 6.2.3 标准库，只发送数值；不支持或未测量交互时保持无样本，不包含 SPA 路由加载性能，也不能替代实验室性能测试。"}}, nil
}
