package executor

import (
	"fmt"
	"local/panel/internal/core"
)

func siteAnalyticsProxy(site core.Site) string {
	endpoint := site.Settings.AnalyticsEndpoint
	if endpoint == "" {
		return ""
	}
	// Validation is also performed by renderSiteConfig; never interpolate an
	// untrusted hostname, URL, configuration fragment or general proxy target.
	if core.ValidateAnalyticsEndpoint(endpoint) != nil {
		return ""
	}
	return fmt.Sprintf(`  # managed analytics proxy; site=%s
  location ^~ /__yunzhan/analytics/ {
    if ($uri !~ "^/__yunzhan/analytics/(tracker[.]js|auto[.]js|event)$") { return 404; }
    proxy_pass http://%s/collect/analytics/;
    proxy_pass_request_headers off;
    proxy_set_header Host $host;
    proxy_set_header Origin $http_origin;
    proxy_set_header User-Agent $http_user_agent;
    proxy_set_header Content-Type $http_content_type;
    proxy_set_header DNT $http_dnt;
    proxy_set_header Sec-GPC $http_sec_gpc;
    proxy_set_header Cookie "";
    proxy_set_header Authorization "";
    proxy_hide_header Set-Cookie;
    proxy_connect_timeout 1s;
    proxy_read_timeout 3s;
    client_max_body_size 4k;
    access_log off;
  }
`, site.ID, endpoint)
}

// Explicit opt-in: import only the immutable, signed context-aware program.
// Body/header handlers must be attached to actual content locations, never
// the health, collector, denied file or PHP diagnostic locations.
func siteAnalyticsHTMLInjection(site core.Site) string {
	if !site.Settings.AnalyticsInjectHTML || site.Settings.AnalyticsEndpoint == "" || !core.ValidID(site.ID) {
		return ""
	}
	return fmt.Sprintf("  # managed analytics HTML injection; site=%s\n  js_engine qjs;\n  js_import analytics_html from %s;\n  set $panel_analytics_site %s;\n", site.ID, analyticsHTMLProgramPath(), site.ID)
}

func siteAnalyticsHTMLFilters(site core.Site) string {
	if !site.Settings.AnalyticsInjectHTML || site.Settings.AnalyticsEndpoint == "" || !core.ValidID(site.ID) {
		return ""
	}
	return "    js_header_filter analytics_html.header;\n    js_body_filter analytics_html.body buffer_type=buffer;\n"
}
