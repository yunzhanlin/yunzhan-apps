package core

import (
	"context"
	"net/http"
	"time"
)

type SiteTrafficDay struct {
	Date     string `json:"date"`
	Bytes    int64  `json:"bytes"`
	Requests int64  `json:"requests"`
}

type SiteTrafficSite struct {
	ID         string `json:"id"`
	TodayBytes int64  `json:"today_bytes"`
}

type SiteTrafficSummary struct {
	Days      []SiteTrafficDay  `json:"days"`
	Sites     []SiteTrafficSite `json:"sites"`
	Partial   bool              `json:"partial"`
	UpdatedAt string            `json:"updated_at"`
}

func (a *Server) siteTrafficRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sites/traffic", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		sites, err := a.Store.Sites()
		if err != nil {
			fail(w, 500, "读取站点失败")
			return
		}
		ids := make([]string, 0, len(sites))
		partial := false
		for _, site := range sites {
			if site.Settings.WebServer == "apache" {
				partial = true
				continue
			}
			ids = append(ids, site.ID)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var result SiteTrafficSummary
		if err = a.Executor.Call(ctx, http.MethodPost, "/v1/sites/traffic", map[string]any{"site_ids": ids}, &result); err != nil {
			fail(w, 503, "站点流量暂不可读取")
			return
		}
		result.Partial = result.Partial || partial
		send(w, 200, result)
	}))
}
