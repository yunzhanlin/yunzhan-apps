package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestHTTPSRenderingKeepsLegacyAndSeparatesForcedRedirect(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "tls.localhost", Settings: core.DefaultSiteSettings(core.SiteSettings{Domains: []string{"alias.example.test"}})}
	root := t.TempDir()
	plain, e := renderSiteConfig(site, root)
	if e != nil {
		t.Fatal(e)
	}
	if renderSiteTLS(site, "", plain) != plain {
		t.Fatal("legacy configuration changed")
	}
	site.Settings.TLS = &core.SiteTLS{CertificateID: core.ID()}
	mixed, e := renderSiteConfig(site, root)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(mixed, "server {") != 1 || !strings.Contains(mixed, "listen 127.0.0.1:19102 ssl;") || !strings.Contains(mixed, "listen 127.0.0.1:19101;") {
		t.Fatal("dual listener missing")
	}
	site.Settings.TLS.Redirect = true
	forced, e := renderSiteConfig(site, root)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(forced, "server {") != 2 {
		t.Fatal("expected separate HTTP/HTTPS virtual servers")
	}
	httpPart := forced[strings.LastIndex(forced, "server {"):]
	if !strings.Contains(httpPart, "return 301 https://$host:19102$request_uri;") || !strings.Contains(httpPart, siteHealthPath(site)) || strings.Contains(httpPart, "fastcgi_pass") || strings.Contains(httpPart, "root ") {
		t.Fatal("HTTP redirect leaked application handlers")
	}
	if !strings.Contains(forced, "/etc/panel/certificates/"+site.Settings.TLS.CertificateID+"/key.pem") {
		t.Fatal("wrong certificate reference")
	}
}

func TestACMEChallengeLocationSurvivesTLSRedirectAndProxy(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "acme.localhost", Settings: core.DefaultSiteSettings(core.SiteSettings{ACME: true, Mode: "proxy", ProxyURL: "http://127.0.0.1:18080", TLS: &core.SiteTLS{CertificateID: core.ID(), Redirect: true}})}
	out, e := renderSiteConfig(site, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(out, "location ^~ /.well-known/acme-challenge/") != 2 {
		t.Fatal("HTTP and HTTPS must both preserve the challenge handler")
	}
	for _, wanted := range []string{`proxy_set_header Host $host;`, `proxy_set_header Cookie "";`, `proxy_pass_request_body off;`, `limit_except GET { deny all; }`} {
		if !strings.Contains(out, wanted) {
			t.Fatal("missing challenge boundary", wanted)
		}
	}
}

func TestStandardPortsRequireExplicitWebsiteIngress(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "www.example.test", Settings: core.DefaultSiteSettings(core.SiteSettings{ACME: true, TLS: &core.SiteTLS{CertificateID: core.ID(), Redirect: true}})}
	root := t.TempDir()
	old, err := renderSiteConfig(site, root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(old, "listen 0.0.0.0:") || strings.Contains(old, "listen [::]:") {
		t.Fatal("private site exposed on standard ports")
	}
	site.Settings.PublicIngress = true
	public, err := renderSiteConfig(site, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen 0.0.0.0:80;", "listen [::]:80;", "listen 0.0.0.0:443 ssl;", "listen [::]:443 ssl;", "listen 127.0.0.1:19101;", "listen 127.0.0.1:19102 ssl;", "return 301 https://$host$request_uri;"} {
		if !strings.Contains(public, want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Contains(public, "https://$host:19102") || strings.Count(public, "location ^~ /.well-known/acme-challenge/") != 2 {
		t.Fatal("wrong redirect or missing challenge")
	}
	if siteHTTPSRedirect(site, site.Domain, "/a?q=%2F") != "https://www.example.test/a?q=%2F" {
		t.Fatal("redirect target")
	}
	site.Settings.PublicIngress = false
	restored, err := renderSiteConfig(site, root)
	if err != nil || restored != old {
		t.Fatal("disabled ingress changes legacy configuration", err)
	}
	site.Settings.PublicIngress = true
	site.Settings.TLS = nil
	plain, err := renderSiteConfig(site, root)
	if err != nil || strings.Contains(plain, ":443") || !strings.Contains(plain, "listen 0.0.0.0:80;") {
		t.Fatal("TLS listener without certificate", err)
	}
}
