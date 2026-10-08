package core

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A rule match is not a request or a confirmed HTTP block. The privacy log
// deliberately contains no IP, request ID, URI, headers or request content.
type WAFBodyEvent struct {
	Time       string `json:"time"`
	SiteID     string `json:"site_id"`
	RuleID     int    `json:"rule_id"`
	Phase      int    `json:"phase"`
	Severity   int    `json:"severity"`
	Disruptive bool   `json:"disruptive_mark"`
}
type WAFBodyEventsPage struct {
	Events            []WAFBodyEvent `json:"events"`
	Available         bool           `json:"available"`
	Partial           bool           `json:"partial"`
	Rejected          int            `json:"rejected_lines"`
	LogBytes          int64          `json:"log_bytes"`
	MaxBytes          int64          `json:"max_bytes"`
	CapacityExhausted bool           `json:"capacity_exhausted"`
	LegacyLog         bool           `json:"legacy_log"`
	BestEffort        bool           `json:"metadata_best_effort"`
}
type WAFBodyReport struct {
	WAFBodyEventsPage
	Matches  int            `json:"rule_matches"`
	Scanned  int            `json:"scanned"`
	Rules    []WAFDimension `json:"rules"`
	Sites    []WAFDimension `json:"sites"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Page     int            `json:"page"`
	Limit    int            `json:"limit"`
	Counting string         `json:"counting_contract"`
}

type WAFBodyLogRetainRequest struct {
	IndexSHA256     string `json:"index_sha256"`
	SnapshotSHA256  string `json:"snapshot_sha256"`
	SnapshotMissing bool   `json:"snapshot_missing"`
	Acknowledged    bool   `json:"acknowledge_unknown_rotation_and_incomplete_snapshot"`
}

type WAFBodyLogIndexRetainRequest struct {
	SHA256       string `json:"sha256"`
	Acknowledged bool   `json:"acknowledge_uncommitted_index_not_applied"`
}

func (in WAFBodyLogIndexRetainRequest) Valid() bool {
	return in.Acknowledged && len(in.SHA256) == 64 && strings.Trim(in.SHA256, "0123456789abcdef") == ""
}

func (in WAFBodyLogRetainRequest) Valid() bool {
	validSHA := func(v string) bool { return len(v) == 64 && strings.Trim(v, "0123456789abcdef") == "" }
	return in.Acknowledged && validSHA(in.IndexSHA256) && (in.SnapshotMissing && in.SnapshotSHA256 == "" || !in.SnapshotMissing && validSHA(in.SnapshotSHA256))
}

func WAFBodyReportQuery(q url.Values, now time.Time) (url.Values, error) {
	for key, values := range q {
		if !containsString([]string{"from", "to", "site_id", "rule", "phase", "page", "limit"}, key) || len(values) != 1 || len(values[0]) > 256 {
			return nil, errors.New("请求体日志筛选字段、长度或重复参数无效")
		}
	}
	for _, field := range []struct {
		name     string
		min, max int
	}{{"rule", 1, 2147483647}, {"phase", 1, 5}} {
		if value := q.Get(field.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < field.min || n > field.max || strconv.Itoa(n) != value {
				return nil, errors.New("请求体规则号或处理阶段无效")
			}
		}
	}
	copy := url.Values{}
	for key, values := range q {
		if key != "phase" {
			copy[key] = append([]string{}, values...)
		}
	}
	query, err := WAFReportQuery(copy, now)
	if err != nil {
		return nil, err
	}
	if q.Get("phase") != "" {
		query.Set("phase", q.Get("phase"))
	}
	return query, nil
}

func BuildWAFBodyReport(snapshot WAFBodyEventsPage, q url.Values, now time.Time) (WAFBodyReport, error) {
	query, err := WAFBodyReportQuery(q, now)
	if err != nil {
		return WAFBodyReport{}, err
	}
	from, _ := time.Parse(time.RFC3339, query.Get("from"))
	to, _ := time.Parse(time.RFC3339, query.Get("to"))
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	out := WAFBodyReport{WAFBodyEventsPage: snapshot, Scanned: len(snapshot.Events), Rules: []WAFDimension{}, Sites: []WAFDimension{}, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Page: page, Limit: limit, Counting: "rule_matches_not_http_requests_or_blocks"}
	out.Events = []WAFBodyEvent{}
	filtered := []WAFBodyEvent{}
	rules, sites := map[string]int{}, map[string]int{}
	for _, event := range snapshot.Events {
		at, err := time.Parse(time.RFC3339, event.Time)
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
	for _, item := range []struct {
		source map[string]int
		target *[]WAFDimension
	}{{rules, &out.Rules}, {sites, &out.Sites}} {
		for name, count := range item.source {
			*item.target = append(*item.target, WAFDimension{name, count})
		}
		sort.Slice(*item.target, func(i, j int) bool {
			a, b := (*item.target)[i], (*item.target)[j]
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

func (a *Server) wafBodyReportRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/software/nginx-waf/body-log/rotation/retain", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可核对自动轮转未知结果")
			return
		}
		var in WAFBodyLogRotationRetainRequest
		if !decode(w, r, &in) {
			return
		}
		if !in.Valid() || len(r.URL.Query()) != 0 {
			fail(w, 400, "自动轮转摘要或未知结果确认无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out any
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/body-log/rotation/retain", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "waf.body-log.rotation-retain", "nginx-waf", "digest-bound unknown outcome retained; no repeated truncate or automatic archive removal")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/nginx-waf/body-log/index-stages/{id}/retain", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可保留未提交索引残件")
			return
		}
		var in WAFBodyLogIndexRetainRequest
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || len(r.URL.Query()) != 0 || !in.Valid() {
			fail(w, 400, "索引残件标识、摘要或不接管确认无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out any
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/body-log/index-stages/"+id+"/retain", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "waf.body-log.index-retain", id, "digest-bound uncommitted index inode preserved privately; never applied; current log untouched")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/nginx-waf/body-log/archives/{id}/retain", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可核对未完成日志事务")
			return
		}
		var in WAFBodyLogRetainRequest
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || len(r.URL.Query()) != 0 || !in.Valid() {
			fail(w, 400, "恢复记录、摘要或未知结果确认无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out any
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/body-log/archives/"+id+"/retain", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "waf.body-log.retain", id, "digest-bound failed snapshot retained; unknown rotation outcome not marked successful; current log untouched")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/nginx-waf/body-log/archives/{id}/remove", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可删除明确选中的日志快照")
			return
		}
		var in struct {
			SHA256       string `json:"sha256"`
			Acknowledged bool   `json:"acknowledge_bounded_export_and_permanent_removal"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || len(in.SHA256) != 64 || strings.Trim(in.SHA256, "0123456789abcdef") != "" || !in.Acknowledged || len(r.URL.Query()) != 0 {
			fail(w, 400, "备份标识、摘要或永久删除确认无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out any
		if err := a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/body-log/archives/"+id+"/remove", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "waf.body-log.remove", id, "selected digest-bound snapshot permanently removed; current log untouched")
		send(w, 200, out)
	}))
	for _, operation := range []struct {
		pattern, method, target string
		write                   bool
	}{
		{"GET /api/software/nginx-waf/body-log/rotation", "GET", "/v1/software/nginx-waf/body-log/rotation", false},
		{"GET /api/software/nginx-waf/body-log/archives", "GET", "/v1/software/nginx-waf/body-log/archives", false},
		{"GET /api/software/nginx-waf/body-log/archives/{id}", "GET", "/v1/software/nginx-waf/body-log/archives/", false},
		{"POST /api/software/nginx-waf/body-log/rotate", "POST", "/v1/software/nginx-waf/body-log/rotate", true},
	} {
		m.HandleFunc(operation.pattern, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			role, _, err := a.Store.appUserRole(u.ID)
			if err != nil || role != "admin" {
				fail(w, 403, "请求体日志治理仅管理员可访问")
				return
			}
			if len(r.URL.Query()) != 0 {
				fail(w, 400, "请求体日志治理不接受自定义路径或查询参数")
				return
			}
			target := operation.target
			if id := r.PathValue("id"); id != "" {
				if !ValidID(id) {
					fail(w, 400, "元数据备份标识无效")
					return
				}
				target += id
			}
			var body any
			if operation.write {
				var in struct{}
				if !decode(w, r, &in) {
					return
				}
				body = in
			}
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			var out any
			if err := a.Executor.Call(ctx, operation.method, target, body, &out); err != nil {
				fail(w, 409, err.Error())
				return
			}
			if operation.write {
				_ = a.Store.Audit(u.Username, "waf.body-log.rotate", "nginx-waf", "same-inode snapshot before truncate; no Nginx reload")
			}
			send(w, 200, out)
		}))
	}
	m.HandleFunc("GET /api/software/nginx-waf/body-report", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "请求体规则日志仅管理员可访问")
			return
		}
		query, err := WAFBodyReportQuery(r.URL.Query(), time.Now())
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if id := query.Get("site_id"); id != "" {
			if _, err := a.Store.Site(id); err != nil {
				fail(w, 404, "网站不存在")
				return
			}
		}
		var out WAFBodyReport
		if err := a.Executor.Call(r.Context(), "GET", "/v1/software/nginx-waf/body-report?"+query.Encode(), nil, &out); err != nil {
			fail(w, 503, err.Error())
			return
		}
		send(w, 200, out)
	}))
}
