package core

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type WAFDimension struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
type WAFReport struct {
	Events   []WAFEvent     `json:"events"`
	Total    int            `json:"total"`
	Blocked  int            `json:"blocked"`
	Observed int            `json:"observed"`
	Sources  int            `json:"sources"`
	Partial  bool           `json:"partial"`
	Scanned  int            `json:"scanned"`
	Rules    []WAFDimension `json:"rules"`
	IPs      []WAFDimension `json:"ips"`
	Sites    []WAFDimension `json:"sites"`
	Hours    []WAFDimension `json:"hours"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Page     int            `json:"page"`
	Limit    int            `json:"limit"`
}

func WAFEventReason(e WAFEvent) string {
	if e.Rate == "REJECTED" {
		return "cc"
	}
	if e.Reason != "" {
		return e.Reason
	}
	if e.BadMethod == "1" {
		return "method"
	}
	if e.BadArgs == "1" {
		return "legacy-args"
	}
	if e.BadURI == "1" {
		return "legacy-uri"
	}
	if e.BadAgent == "1" {
		return "scanner"
	}
	return "unknown"
}
func WAFReportQuery(q url.Values, now time.Time) (url.Values, error) {
	for k, xs := range q {
		if !containsString([]string{"from", "to", "site_id", "site_domain", "ip", "rule", "action", "page", "limit"}, k) || len(xs) != 1 || len(xs[0]) > 256 {
			return nil, errors.New("日志筛选字段或长度无效")
		}
	}
	if id := q.Get("site_id"); id != "" && !ValidID(id) {
		return nil, errors.New("网站标识无效")
	}
	if ip := q.Get("ip"); ip != "" {
		if _, e := netip.ParseAddr(ip); e != nil {
			return nil, errors.New("筛选 IP 无效")
		}
	}
	if action := q.Get("action"); action != "" && action != "block" && action != "observe" {
		return nil, errors.New("筛选动作无效")
	}
	start, end := now.Add(-24*time.Hour), now
	for _, key := range []string{"from", "to"} {
		if value := q.Get(key); value != "" {
			v, e := time.Parse(time.RFC3339, value)
			if e != nil {
				return nil, errors.New("时间应为 RFC3339")
			}
			if key == "from" {
				start = v
			} else {
				end = v
			}
		}
	}
	if !start.Before(end) || end.Sub(start) > 90*24*time.Hour {
		return nil, errors.New("日志时间范围应在 90 天内")
	}
	q.Set("from", start.UTC().Format(time.RFC3339))
	q.Set("to", end.UTC().Format(time.RFC3339))
	for _, x := range []struct {
		key      string
		def, max int
	}{{"page", 1, 10000}, {"limit", 100, 5000}} {
		n := x.def
		if q.Get(x.key) != "" {
			v, e := strconv.Atoi(q.Get(x.key))
			if e != nil || v < 1 || v > x.max {
				return nil, errors.New("日志分页参数无效")
			}
			n = v
		}
		q.Set(x.key, strconv.Itoa(n))
	}
	return q, nil
}
func BuildWAFReport(snapshot WAFEventsPage, q url.Values, now time.Time) (WAFReport, error) {
	query, e := WAFReportQuery(q, now)
	if e != nil {
		return WAFReport{}, e
	}
	start, _ := time.Parse(time.RFC3339, query.Get("from"))
	end, _ := time.Parse(time.RFC3339, query.Get("to"))
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	out := WAFReport{Events: []WAFEvent{}, Partial: snapshot.HasMore, Scanned: len(snapshot.Events), From: start.Format(time.RFC3339), To: end.Format(time.RFC3339), Page: page, Limit: limit}
	maps := map[string]map[string]int{}
	for _, k := range []string{"rules", "ips", "sites", "hours"} {
		maps[k] = map[string]int{}
	}
	filtered := []WAFEvent{}
	for _, event := range snapshot.Events {
		t, e := time.Parse(time.RFC3339, event.Time)
		if e != nil || t.Before(start) || t.After(end) {
			continue
		}
		if id := query.Get("site_id"); id != "" && event.SiteID != id && (event.SiteID != "" || event.Site != query.Get("site_domain")) {
			continue
		}
		if ip := query.Get("ip"); ip != "" && event.IP != ip {
			continue
		}
		event.Reason = WAFEventReason(event)
		if event.Action == "" {
			event.Action = "block"
		}
		if rule := query.Get("rule"); rule != "" && event.Reason != rule {
			continue
		}
		if action := query.Get("action"); action != "" && event.Action != action {
			continue
		}
		filtered = append(filtered, event)
		if event.Action == "observe" {
			out.Observed++
		} else {
			out.Blocked++
		}
		maps["rules"][event.Reason]++
		maps["ips"][event.IP]++
		maps["sites"][event.Site]++
		maps["hours"][t.UTC().Format("2006-01-02 15:00")]++
	}
	out.Total = len(filtered)
	out.Sources = len(maps["ips"])
	for key, m := range maps {
		xs := []WAFDimension{}
		for name, count := range m {
			xs = append(xs, WAFDimension{name, count})
		}
		sort.Slice(xs, func(i, j int) bool {
			if key == "hours" {
				return xs[i].Name < xs[j].Name
			}
			if xs[i].Count == xs[j].Count {
				return xs[i].Name < xs[j].Name
			}
			return xs[i].Count > xs[j].Count
		})
		if key != "hours" && len(xs) > 20 {
			xs = xs[:20]
		}
		switch key {
		case "rules":
			out.Rules = xs
		case "ips":
			out.IPs = xs
		case "sites":
			out.Sites = xs
		case "hours":
			out.Hours = xs
		}
	}
	first := (page - 1) * limit
	if first < len(filtered) {
		out.Events = filtered[first:min(first+limit, len(filtered))]
	}
	return out, nil
}

func (a *Server) wafWorkspaceRoutes(m *http.ServeMux) {
	admin := func(u identity, w http.ResponseWriter) bool {
		role, _, e := a.Store.appUserRole(u.ID)
		if e != nil || role != "admin" {
			fail(w, 403, "防火墙全局配置和日志仅管理员可访问")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/nginx-waf/config", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(u, w) {
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/software/nginx-waf/config", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/nginx-waf/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(u, w) {
			return
		}
		var in struct {
			Settings map[string]any `json:"settings"`
		}
		if !decode(w, r, &in) {
			return
		}
		v, e := DecodeWAFConfig(in.Settings)
		if e == nil {
			e = a.Store.validateWAFSites(v)
		}
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out any
		if e = a.Executor.Call(r.Context(), "POST", "/v1/software/nginx-waf/preview", WAFSettings(v), &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/nginx-waf/report", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(u, w) {
			return
		}
		q, e := WAFReportQuery(r.URL.Query(), time.Now())
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		q.Del("site_domain")
		if id := q.Get("site_id"); id != "" {
			site, e := a.Store.Site(id)
			if e != nil {
				fail(w, 404, "网站不存在")
				return
			}
			q.Set("site_domain", site.Domain)
		}
		var out WAFReport
		if e = a.Executor.Call(r.Context(), "GET", "/v1/software/nginx-waf/report?"+q.Encode(), nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/nginx-waf/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !admin(u, w) {
			return
		}
		rows, e := a.Store.DB.QueryContext(r.Context(), `SELECT id,kind,state,error,created_at,updated_at FROM runtime_jobs WHERE target_id='nginx-waf' ORDER BY created_at DESC,id DESC LIMIT 50`)
		if e != nil {
			fail(w, 500, "读取防火墙操作记录失败")
			return
		}
		defer rows.Close()
		type entry struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			State   string `json:"state"`
			Error   string `json:"error"`
			Created string `json:"created_at"`
			Updated string `json:"updated_at"`
		}
		xs := []entry{}
		for rows.Next() {
			var x entry
			if e = rows.Scan(&x.ID, &x.Kind, &x.State, &x.Error, &x.Created, &x.Updated); e != nil {
				fail(w, 500, "读取防火墙操作记录失败")
				return
			}
			xs = append(xs, x)
		}
		if rows.Err() != nil {
			fail(w, 500, "读取防火墙操作记录失败")
			return
		}
		send(w, 200, map[string]any{"entries": xs})
	}))
}
