package executor

import (
	"context"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsRenderingAndActualDomainConflicts(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) {
		t.Fatal("preview executed system command")
		return "", nil
	})
	site := core.Site{ID: core.ID(), Name: "config", Slug: "config-site", Domain: "config-site.localhost", Settings: core.DefaultSiteSettings(core.SiteSettings{Domains: []string{"alias.example.test"}})}
	public := filepath.Join(s.Config.SitesDir, site.ID, "public")
	if e := os.MkdirAll(public, 0755); e != nil {
		t.Fatal(e)
	}
	rendered, e := renderSiteConfig(site, public)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"server_name config-site.localhost alias.example.test;", "index index.html;", "disable_symlinks on;", siteHealthPath(site), "panel_site;"} {
		if !strings.Contains(rendered, want) {
			t.Fatal("missing configuration", want)
		}
	}
	site.Settings.Mode = "redirect"
	site.Settings.RedirectURL = "https://example.test"
	site.Settings.PreserveURI = true
	rendered, e = renderSiteConfig(site, public)
	if e != nil || !strings.Contains(rendered, `return 302 "https://example.test$request_uri";`) {
		t.Fatal("redirect rendering", e)
	}
	os.Mkdir(filepath.Join(public, "app"), 0755)
	site.Settings.DocumentRoot = "app"
	if _, e = renderSiteConfig(site, public); e != nil {
		t.Fatal(e)
	}
	os.Symlink(t.TempDir(), filepath.Join(public, "outside"))
	site.Settings.DocumentRoot = "outside"
	if _, e = renderSiteConfig(site, public); e == nil {
		t.Fatal("linked document root accepted")
	}
	os.WriteFile(filepath.Join(s.Config.ConfDir, core.ID()+".conf"), []byte("server {\n server_name alias.example.test;\n}\n"), 0644)
	if e = s.checkDomainOwners(site); e == nil {
		t.Fatal("actual domain conflict ignored")
	}
}

func TestSiteWAFCanBeDisabledWithoutReenableOnGlobalConfigure(t *testing.T) {
	root := t.TempDir()
	disabled := false
	site := core.Site{ID: core.ID(), Domain: "waf.localhost", Settings: core.DefaultSiteSettings(core.SiteSettings{WAFEnabled: &disabled})}
	defaultConfig, err := renderSiteConfig(core.Site{ID: site.ID, Domain: site.Domain, Settings: core.DefaultSiteSettings(core.SiteSettings{})}, root)
	if err != nil || strings.Count(defaultConfig, "include /etc/panel/waf/server.d/*.conf;") != 1 {
		t.Fatal("existing sites must remain protected by default", err)
	}
	for _, redirect := range []bool{false, true} {
		site.Settings.TLS = nil
		if redirect {
			site.Settings.TLS = &core.SiteTLS{CertificateID: core.ID(), Redirect: true}
		}
		config, err := renderSiteConfig(site, root)
		if err != nil || !strings.Contains(config, "panel-waf-disabled") || strings.Contains(config, "include /etc/panel/waf/server.d/*.conf;") {
			t.Fatal("disabled site still loads WAF in an HTTP or HTTPS server", err)
		}
	}
}

func TestManagedAppProxyPreservesOriginalHostOnlyWhenSelected(t *testing.T) {
	site := core.Site{ID: core.ID(), Name: "WordPress", Slug: "wordpress-site", Domain: "blog.example.test", Settings: core.DefaultSiteSettings(core.SiteSettings{Mode: "proxy", ProxyURL: "http://127.0.0.1:18480", ProxyPreserveHost: true})}
	root := t.TempDir()
	config, err := renderSiteConfig(site, root)
	if err != nil || !strings.Contains(config, "proxy_set_header Host $host;") {
		t.Fatal("managed app did not preserve original host", err)
	}
	site.Settings.ProxyPreserveHost = false
	config, err = renderSiteConfig(site, root)
	if err != nil || !strings.Contains(config, "proxy_set_header Host $proxy_host;") {
		t.Fatal("regular proxy host behavior changed", err)
	}
}

func TestThinkPHPCompatibilityLocationPrecedesGenericPHPBlock(t *testing.T) {
	site := core.Site{
		ID:           core.ID(),
		Name:         "ThinkPHP",
		Slug:         "thinkphp-site",
		Domain:       "thinkphp-site.localhost",
		PHPVersionID: "php-8.5.10",
		Settings:     core.DefaultSiteSettings(core.SiteSettings{Rewrite: "thinkphp"}),
	}
	compat := thinkPHPCompatibilityLocation(site, "/run/php.sock")
	for _, want := range []string{
		`^/(?:api|admin)\.php(?:/|$)`,
		`fastcgi_param SCRIPT_FILENAME $document_root/index.php;`,
		`fastcgi_param PATH_INFO $uri;`,
		`fastcgi_pass unix:/run/php.sock;`,
	} {
		if !strings.Contains(compat, want) {
			t.Fatalf("ThinkPHP compatibility location missing %q: %s", want, compat)
		}
	}
	if strings.Contains(compat, "try_files") {
		t.Fatalf("ThinkPHP compatibility location mutates PATH_INFO through try_files: %s", compat)
	}
	site.Settings.Rewrite = "wordpress"
	if got := thinkPHPCompatibilityLocation(site, "/run/php.sock"); got != "" {
		t.Fatalf("non-ThinkPHP site received compatibility location: %s", got)
	}
}

func TestSiteErrorLogsRedactRequestQueries(t *testing.T) {
	value := `request: "GET /login?token=secret&password=value HTTP/1.1", upstream: "http://127.0.0.1/login?api_key=secret"`
	redacted := redactSiteLog(value)
	if strings.Contains(redacted, "secret") || strings.Contains(redacted, "value") || !strings.Contains(redacted, "/login?") {
		t.Fatal(redacted)
	}
}

type siteTestTransport func(*http.Request) (*http.Response, error)

func (f siteTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHomepageVerificationRejectsOldGenerationAndWrongBehavior(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "probe.localhost", PHPVersionID: "php-8.4.25", Settings: core.DefaultSiteSettings(core.SiteSettings{Mode: "redirect", RedirectURL: "https://example.test", RedirectCode: 307})}
	for _, tc := range []struct {
		code   int
		marker string
		ok     bool
	}{{200, "old", false}, {307, "old", false}, {200, core.Hash(siteHealthBody(site)), false}, {502, core.Hash(siteHealthBody(site)), false}, {307, core.Hash(siteHealthBody(site)), true}} {
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: siteTestTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.code, Header: http.Header{"X-Panel-Config": []string{tc.marker}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})}
		_, e := verifySiteHomepage(context.Background(), client, site)
		if (e == nil) != tc.ok {
			t.Fatalf("code=%d marker=%s err=%v", tc.code, tc.marker, e)
		}
	}
	before := siteHealthBody(site)
	site.Settings.RedirectCode = 302
	if siteHealthBody(site) == before {
		t.Fatal("configuration change retained verification token")
	}
	before = siteHealthBody(site)
	site.PHPVersionID = "php-8.5.10"
	if siteHealthBody(site) == before {
		t.Fatal("PHP binding change retained verification token")
	}
}
