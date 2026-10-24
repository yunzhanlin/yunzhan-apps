package core

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// These are best-effort rule-match records, not request receipts. The native
// writer omits addresses, URLs, headers, body bytes and rule message text.
type ApacheBodyEvent struct {
	Time        string `json:"time"`
	Engine      string `json:"engine_version"`
	SiteID      string `json:"site_id"`
	RuleID      int    `json:"rule_id"`
	Phase       int    `json:"phase"`
	Severity    int    `json:"severity"`
	Mode        string `json:"mode"`
	Intercepted bool   `json:"intercepted_mark"`
}

type ApacheBodyEventsPage struct {
	Events            []ApacheBodyEvent `json:"events"`
	Available         bool              `json:"available"`
	Partial           bool              `json:"partial"`
	Rejected          int               `json:"rejected_lines"`
	LogBytes          int64             `json:"log_bytes"`
	MaxBytes          int64             `json:"max_bytes"`
	CapacityNearLimit bool              `json:"capacity_near_limit"`
	BestEffort        bool              `json:"metadata_best_effort"`
}

type ApacheBodyReport struct {
	ApacheBodyEventsPage
	Matches  int            `json:"rule_matches"`
	Scanned  int            `json:"scanned"`
	Rules    []WAFDimension `json:"rules"`
	Sites    []WAFDimension `json:"sites"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Page     int            `json:"page"`
	Limit    int            `json:"limit"`
	Counting string         `json:"counting_contract"`
	Scope    string         `json:"scope"`
}

const ApacheBodyCountingContract = "rule_matches_not_unique_requests_or_confirmed_http_blocks"
const ApacheBodyMetadataEngine = "2.9.15-yz5"
const ApacheBodyReportScope = "fixed_numeric_metadata_only_not_activation_health_or_request_receipts"

func ApacheBodyReportQuery(q url.Values, now time.Time) (url.Values, error) {
	for _, field := range []struct {
		name string
		max  int
	}{{"rule", 99999999}, {"limit", 1000}, {"page", 10000}} {
		if value := q.Get(field.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > field.max || strconv.Itoa(n) != value {
				return nil, errors.New("Apache 数值日志规则或分页超出固定范围")
			}
		}
	}
	return WAFBodyReportQuery(q, now)
}

func validApacheBodyEvent(event ApacheBodyEvent) bool {
	at, err := time.Parse(time.RFC3339Nano, event.Time)
	return err == nil && at.UnixMicro() > 0 && at.Year() <= 9999 && event.Engine == ApacheBodyMetadataEngine && ValidID(event.SiteID) && event.RuleID > 0 && event.RuleID <= 99999999 && event.Phase >= 1 && event.Phase <= 5 && event.Severity >= 0 && event.Severity <= 7 && (event.Mode == "block" || event.Mode == "observe") && (!event.Intercepted || event.Mode == "block")
}

func BuildApacheBodyReport(snapshot ApacheBodyEventsPage, q url.Values, now time.Time) (ApacheBodyReport, error) {
	query, err := ApacheBodyReportQuery(q, now)
	if err != nil {
		return ApacheBodyReport{}, err
	}
	if len(snapshot.Events) > 5000 {
		return ApacheBodyReport{}, errors.New("Apache 数值日志快照超过固定记录限额")
	}
	from, _ := time.Parse(time.RFC3339, query.Get("from"))
	to, _ := time.Parse(time.RFC3339, query.Get("to"))
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	out := ApacheBodyReport{ApacheBodyEventsPage: snapshot, Scanned: len(snapshot.Events), Rules: []WAFDimension{}, Sites: []WAFDimension{}, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Page: page, Limit: limit, Counting: ApacheBodyCountingContract, Scope: ApacheBodyReportScope}
	out.Events = []ApacheBodyEvent{}
	filtered := []ApacheBodyEvent{}
	rules, sites := map[string]int{}, map[string]int{}
	for _, event := range snapshot.Events {
		if !validApacheBodyEvent(event) {
			return ApacheBodyReport{}, errors.New("Apache 数值日志快照含无效或未审核程序的记录")
		}
		at, err := time.Parse(time.RFC3339Nano, event.Time)
		if err != nil || at.Before(from) || at.After(to) {
			continue
		}
		if value := query.Get("site_id"); value != "" && value != event.SiteID {
			continue
		}
		if value := query.Get("rule"); value != "" && value != strconv.Itoa(event.RuleID) {
			continue
		}
		if value := query.Get("phase"); value != "" && value != strconv.Itoa(event.Phase) {
			continue
		}
		filtered = append(filtered, event)
		rules[strconv.Itoa(event.RuleID)]++
		sites[event.SiteID]++
	}
	out.Matches = len(filtered)
	for _, dimension := range []struct {
		source map[string]int
		target *[]WAFDimension
	}{{rules, &out.Rules}, {sites, &out.Sites}} {
		for name, count := range dimension.source {
			*dimension.target = append(*dimension.target, WAFDimension{name, count})
		}
		sort.Slice(*dimension.target, func(i, j int) bool {
			a, b := (*dimension.target)[i], (*dimension.target)[j]
			if a.Count != b.Count {
				return a.Count > b.Count
			}
			return a.Name < b.Name
		})
	}
	first := (page - 1) * limit
	if first < len(filtered) {
		out.Events = filtered[first:min(first+limit, len(filtered))]
	}
	return out, nil
}

func (a *Server) apacheBodyReportRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/apache-waf/body-report", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可读取 Apache 数值规则匹配记录")
			return
		}
		query, err := ApacheBodyReportQuery(r.URL.Query(), time.Now())
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var out ApacheBodyReport
		if err := a.Executor.Call(ctx, "GET", "/v1/software/apache-waf/body-report?"+query.Encode(), nil, &out); err != nil {
			fail(w, 503, "Apache 数值日志读取未完成，未当成零匹配："+err.Error())
			return
		}
		page, _ := strconv.Atoi(query.Get("page"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		if out.Counting != ApacheBodyCountingContract || !out.BestEffort || out.Page != page || out.Limit != limit || out.From != query.Get("from") || out.To != query.Get("to") || len(out.Events) > out.Limit || out.Matches < len(out.Events) || out.Scanned < out.Matches || out.Scanned > 5000 || out.LogBytes < 0 || out.LogBytes > 32<<20 || out.MaxBytes != 32<<20 || out.Scope != ApacheBodyReportScope || out.Rejected < 0 || (!out.Available && (out.Scanned != 0 || out.LogBytes != 0)) || (!out.Partial && (out.Rejected > 0 || out.CapacityNearLimit)) {
			fail(w, 503, "Apache 数值日志响应身份或统计范围不完整，未当成已核验报告")
			return
		}
		for _, event := range out.Events {
			if !validApacheBodyEvent(event) {
				fail(w, 503, "Apache 数值日志响应含无效记录，未返回未核实内容")
				return
			}
		}
		for index, dimensions := range [][]WAFDimension{out.Rules, out.Sites} {
			seen, count := map[string]bool{}, 0
			for _, dimension := range dimensions {
				n, err := strconv.Atoi(dimension.Name)
				validName := ValidID(dimension.Name)
				if index == 0 {
					validName = err == nil && n > 0 && n <= 99999999 && strconv.Itoa(n) == dimension.Name
				}
				if !validName || seen[dimension.Name] || dimension.Count < 1 || dimension.Count > out.Matches {
					fail(w, 503, "Apache 数值日志维度统计无法核实")
					return
				}
				seen[dimension.Name] = true
				count += dimension.Count
			}
			if count != out.Matches {
				fail(w, 503, "Apache 数值日志统计不完整，未返回局部结果冒充完整")
				return
			}
		}
		send(w, 200, out)
	}))
}
