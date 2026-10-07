package core

import (
	"errors"
	"net/http"
	"time"
)

const ApacheWAFVersion = "2.0.0"

func DefaultApacheWAFConfig() WAFConfig {
	cfg := DefaultWAFConfig()
	cfg.Policy.CCEnabled = false
	return cfg
}

func DecodeApacheWAFConfig(raw map[string]any) (WAFConfig, error) {
	if len(raw) == 0 {
		return DefaultApacheWAFConfig(), nil
	}
	cfg, err := DecodeWAFConfig(raw)
	if err != nil {
		return cfg, err
	}
	if cfg.Body != nil {
		return cfg, errors.New("Apache 尚未实现原生请求体引擎；不能保存 Nginx 请求体策略冒充生效")
	}
	if cfg.Policy.CCEnabled || len(cfg.Policy.CCRules) != 0 {
		return cfg, errors.New("Apache 元数据防护不提供 CC 限速；请关闭 CC 并通过 Nginx 入口配置限速")
	}
	for _, site := range cfg.Policy.Sites {
		if site.CCEnabled != nil && *site.CCEnabled || site.Rate != 0 || site.Burst != 0 {
			return cfg, errors.New("Apache 站点策略不接受独立 CC 速率或容量")
		}
	}
	return cfg, nil
}

func (s *Store) validateApacheWAFSites(cfg WAFConfig) error {
	for _, id := range WAFScopedSites(cfg) {
		site, err := s.Site(id)
		if err != nil || site.Status == "stopped" || DefaultSiteSettings(site.Settings).WebServer != "apache" {
			return errors.New("Apache 防护策略只支持正在运行的 Apache 受管网站")
		}
	}
	return nil
}

func (a *Server) apacheWAFWorkspaceRoutes(m *http.ServeMux) {
	for _, operation := range []string{"config", "report"} {
		m.HandleFunc("GET /api/software/apache-waf/"+operation, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			path := "/v1/software/apache-waf/" + operation
			if operation == "report" {
				query, err := WAFReportQuery(r.URL.Query(), time.Now())
				if err != nil {
					fail(w, 400, err.Error())
					return
				}
				query.Del("site_domain")
				path += "?" + query.Encode()
			}
			var out any
			if err := a.Executor.Call(r.Context(), "GET", path, nil, &out); err != nil {
				fail(w, 503, err.Error())
				return
			}
			send(w, 200, out)
		}))
	}
	m.HandleFunc("POST /api/software/apache-waf/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Settings map[string]any `json:"settings"`
		}
		if !decode(w, r, &in) {
			return
		}
		cfg, err := DecodeApacheWAFConfig(in.Settings)
		if err == nil {
			err = a.Store.validateApacheWAFSites(cfg)
		}
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		var out any
		if err = a.Executor.Call(r.Context(), "POST", "/v1/software/apache-waf/preview", WAFSettings(cfg), &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/apache-waf/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		rows, err := a.Store.DB.QueryContext(r.Context(), `SELECT id,kind,state,error,created_at FROM runtime_jobs WHERE target_id='apache-waf' ORDER BY created_at DESC,id DESC LIMIT 50`)
		if err != nil {
			fail(w, 500, "读取操作记录失败")
			return
		}
		defer rows.Close()
		entries := []map[string]any{}
		for rows.Next() {
			var id, kind, state, message, at string
			if err = rows.Scan(&id, &kind, &state, &message, &at); err != nil {
				fail(w, 500, "读取操作记录失败")
				return
			}
			entries = append(entries, map[string]any{"id": id, "kind": kind, "state": state, "error": message, "created_at": at})
		}
		if rows.Err() != nil {
			fail(w, 500, "读取操作记录失败")
			return
		}
		send(w, 200, map[string]any{"entries": entries})
	}))
}
