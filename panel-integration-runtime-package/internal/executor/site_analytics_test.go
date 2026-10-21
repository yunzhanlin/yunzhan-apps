package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestSiteAnalyticsProxyRenderingAndRemovalAcrossIngressModes(t *testing.T) {
	for _, mode := range []string{"files", "proxy", "redirect", "apache", "tls-redirect"} {
		t.Run(mode, func(t *testing.T) {
			site := core.Site{ID: core.ID(), Domain: "analytics.example", Settings: core.DefaultSiteSettings(core.SiteSettings{AnalyticsEndpoint: "127.0.0.1:19220", Domains: []string{"alias.example"}})}
			switch mode {
			case "proxy":
				site.Settings.Mode = "proxy"
				site.Settings.ProxyURL = "http://127.0.0.1:18080"
			case "redirect":
				site.Settings.Mode = "redirect"
				site.Settings.RedirectURL = "https://example.com"
			case "apache":
				site.Settings.WebServer = "apache"
			case "tls-redirect":
				site.Settings.TLS = &core.SiteTLS{CertificateID: core.ID(), Redirect: true}
				site.Settings.PublicIngress = true
			}
			root := t.TempDir()
			enabled, err := renderSiteConfig(site, root)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(enabled, "location ^~ /__yunzhan/analytics/") != 1 || !strings.Contains(enabled, "proxy_pass http://127.0.0.1:19220/collect/analytics/;") || strings.Contains(enabled, "19100/collect") {
				t.Fatal("incorrect proxy", enabled)
			}
			for _, required := range []string{"tracker[.]js|auto[.]js|event", "proxy_pass_request_headers off;", "proxy_set_header Origin $http_origin;", "proxy_set_header Content-Type $http_content_type;", "proxy_set_header Cookie \"\";", "proxy_set_header DNT $http_dnt;", "client_max_body_size 4k;", "access_log off;"} {
				if !strings.Contains(enabled, required) {
					t.Fatal(required)
				}
			}
			site.Settings.AnalyticsEndpoint = ""
			disabled, err := renderSiteConfig(site, root)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(disabled, "/__yunzhan/analytics/") || strings.Contains(disabled, "/collect/analytics/") || !strings.Contains(disabled, "server_name analytics.example alias.example;") {
				t.Fatal("proxy not removed or site lost", disabled)
			}
		})
	}
	site := core.Site{ID: core.ID(), Domain: "analytics.example", Settings: core.SiteSettings{AnalyticsEndpoint: "evil.example:80"}}
	if _, err := renderSiteConfig(site, t.TempDir()); err == nil {
		t.Fatal("untrusted upstream interpolated")
	}
}

func TestSiteAnalyticsHTMLUsesContextAwareLocationFiltersOnly(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "analytics.example", Settings: core.DefaultSiteSettings(core.SiteSettings{AnalyticsEndpoint: "127.0.0.1:19220", AnalyticsInjectHTML: true})}
	content, err := renderSiteConfig(site, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"js_engine qjs;", "js_import analytics_html from " + analyticsHTMLProgramPath() + ";", "set $panel_analytics_site " + site.ID + ";", "location / {\n    js_header_filter analytics_html.header;\n    js_body_filter analytics_html.body buffer_type=buffer;"} {
		if !strings.Contains(content, want) {
			t.Fatal("missing context-aware filter", want, content)
		}
	}
	if strings.Contains(content, "sub_filter") || strings.Count(content, "js_body_filter") != 1 {
		t.Fatal("unsafe or broad filter", content)
	}
	site.Settings.AnalyticsInjectHTML = false
	disabled, err := renderSiteConfig(site, t.TempDir())
	if err != nil || strings.Contains(disabled, "js_body_filter") || strings.Contains(disabled, "js_import") || !strings.Contains(disabled, "location ^~ /__yunzhan/analytics/") {
		t.Fatal("HTML opt-out affected manual proxy", err, disabled)
	}
	if _, err := verifiedAnalyticsHTMLProgram(); err != nil {
		t.Fatal(err)
	}
}
