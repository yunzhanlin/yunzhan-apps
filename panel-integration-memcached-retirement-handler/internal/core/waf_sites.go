package core

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// These are the only website fields needed by the authorized WAF workspace.
// A software/security grant must not become general website/file access.
type wafSiteSettings struct {
	WAFEnabled bool   `json:"waf_enabled"`
	WebServer  string `json:"web_server"`
}

type wafSiteChoice struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Domain   string          `json:"domain"`
	Status   string          `json:"status"`
	Settings wafSiteSettings `json:"settings"`
}

type wafSitePage struct {
	Sites      []wafSiteChoice `json:"sites"`
	NextCursor string          `json:"next_cursor"`
}

func (a *Server) wafSiteRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/{id}/sites", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		w.Header().Set("Cache-Control", "no-store")
		app := r.PathValue("id")
		if app != "nginx-waf" && app != "apache-waf" {
			fail(w, 400, "防火墙标识无效")
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		cursor := ""
		if err != nil || len(r.URL.RawQuery) > 128 || r.URL.ForceQuery || len(q) > 1 || len(q) == 1 && (len(q["cursor"]) != 1 || !ValidID(q.Get("cursor"))) {
			fail(w, 400, "防火墙网站分页字段无效")
			return
		}
		if len(q) == 1 {
			cursor = q.Get("cursor")
		}
		server := "nginx"
		if app == "apache-waf" {
			server = "apache"
		}
		// Stable ID-keyset pages, bounded to 128 results. Never send document
		// roots, proxy credentials/URLs, PHP/TLS, rewrites or account fields.
		rows, err := a.Store.DB.QueryContext(r.Context(), `SELECT id,name,domain,status,settings_json FROM sites WHERE status!='archived' AND id>? AND COALESCE(NULLIF(json_extract(settings_json,'$.web_server'),''),'nginx')=? ORDER BY id LIMIT 129`, cursor, server)
		if err != nil {
			fail(w, 503, "防火墙网站信息暂时不可读取")
			return
		}
		defer rows.Close()
		out := wafSitePage{Sites: []wafSiteChoice{}}
		for rows.Next() {
			var site wafSiteChoice
			var raw string
			if err = rows.Scan(&site.ID, &site.Name, &site.Domain, &site.Status, &raw); err != nil {
				fail(w, 503, "防火墙网站信息暂时不可读取")
				return
			}
			var settings SiteSettings
			if len(raw) > 65536 || json.Unmarshal([]byte(raw), &settings) != nil || !ValidID(site.ID) || len(site.Name) > 160 || !ValidDomain(site.Domain) || len(site.Status) > 80 {
				fail(w, 409, "防火墙网站信息不可核对；未返回部分列表")
				return
			}
			settings = DefaultSiteSettings(settings)
			if settings.WebServer != server {
				fail(w, 409, "防火墙网站服务标识不可核对")
				return
			}
			if len(out.Sites) == 128 {
				out.NextCursor = out.Sites[127].ID
				break
			}
			site.Settings = wafSiteSettings{WAFEnabled: SiteWAFEnabled(settings), WebServer: server}
			out.Sites = append(out.Sites, site)
		}
		if rows.Err() != nil {
			fail(w, 503, "防火墙网站信息暂时不可读取；未返回部分列表")
			return
		}
		send(w, 200, out)
	}))
}
