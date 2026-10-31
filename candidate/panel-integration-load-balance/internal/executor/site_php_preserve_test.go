package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func phpSwitchFixture(t *testing.T) (core.Site, core.Site, string) {
	t.Helper()
	old := core.Site{ID: core.ID(), Name: "PHP preservation", Slug: "php-preserve", Domain: "php-preserve.localhost", Status: "running", PHPVersionID: "php-8.4.25", Settings: core.DefaultSiteSettings(core.SiteSettings{Rewrite: "thinkphp"})}
	old.RuntimeInstanceID = core.PHPInstanceID(old)
	next := old
	next.PHPVersionID = "php-8.4.27"
	source, err := renderSiteConfig(old, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// macOS deliberately renders no executable PHP locations. Supply the
	// real Linux-style fixture explicitly to exercise the platform-neutral
	// parser on both development hosts and native Linux CI.
	if !strings.Contains(source, "fastcgi_pass ") {
		socket := "unix:/run/panel-php-" + core.PHPInstanceID(old) + "/fpm.sock"
		source = strings.Replace(source, "server {\n", "server {\n  location ~ \\.php$ { fastcgi_pass "+socket+"; }\n", 1)
	}
	custom := `  autoindex off;
  # fastcgi_pass unix:/run/panel-php-pretend/fpm.sock; location = /__panel_health_pretend {}
  if ($uri ~* "^/(?:app|config|vendor|runtime)(?:[/.]|$)") { return 404; }
  add_header X-Operator "quoted { fastcgi_pass unix:/run/panel-php-pretend/fpm.sock; }";
  location ~* \.(?:css|js|png)$ { expires 7d; access_log off; try_files $uri =404; }
`
	source = strings.Replace(source, "server {\n", "server {\n"+custom, 1)
	return old, next, source
}

func TestPHPSwitchPreservesEveryCustomByteAndRoundTrip(t *testing.T) {
	old, next, source := phpSwitchFixture(t)
	got, err := phpSwitchNginxConfig(source, old, next, true)
	if err != nil {
		t.Fatal(err)
	}
	oldSocket := "unix:/run/panel-php-" + core.PHPInstanceID(old) + "/fpm.sock"
	newSocket := "unix:/run/panel-php-" + core.PHPInstanceID(next) + "/fpm.sock"
	expected := strings.ReplaceAll(source, "fastcgi_pass "+oldSocket+";", "fastcgi_pass "+newSocket+";")
	expected = strings.ReplaceAll(expected, siteHealthBody(old), siteHealthBody(next))
	expected = strings.ReplaceAll(expected, core.Hash(siteHealthBody(old)), core.Hash(siteHealthBody(next)))
	if got != expected {
		t.Fatal("PHP-only switch altered operator configuration")
	}
	next.RuntimeInstanceID = core.PHPInstanceID(next)
	restored, err := phpSwitchNginxConfig(got, next, old, true)
	if err != nil || restored != source {
		t.Fatal("exact custom configuration round trip", err)
	}
}

func TestPHPSwitchLegacyAndTLSAndStoppedConfigurations(t *testing.T) {
	old, next, source := phpSwitchFixture(t)
	lines := strings.SplitAfter(source, "\n")
	legacy := ""
	for _, line := range lines {
		if !strings.Contains(line, "location = "+siteHealthPath(old)) && !strings.Contains(line, "add_header X-Panel-Config") {
			legacy += line
		}
	}
	got, err := phpSwitchNginxConfig(legacy, old, next, true)
	if err != nil || !strings.Contains(got, "autoindex off;") || strings.Count(got, siteHealthPath(next)) != 1 {
		t.Fatal("legacy upgrade", err)
	}
	// A second TLS/redirect server retains its own listener and location bytes.
	tail := "server { listen 443 ssl; server_name " + old.Domain + "; location / { return 302 https://example.test; } }\n"
	got, err = phpSwitchNginxConfig(legacy+tail, old, next, true)
	if err != nil || strings.Count(got, "location = "+siteHealthPath(next)) != 2 || !strings.Contains(got, "listen 443 ssl;") {
		t.Fatal("two server upgrade", err)
	}
	disabled := "# managed by panel; site=" + old.ID + "; disabled\n"
	if got, err = phpSwitchNginxConfig(disabled, old, next, false); err != nil || got != disabled {
		t.Fatal("stopped site changed", err)
	}
	if _, err = phpSwitchNginxConfig(source, old, next, false); err == nil {
		t.Fatal("running configuration accepted as stopped")
	}
}

func TestPHPSwitchRejectsAmbiguousForeignAndMalformedConfigurations(t *testing.T) {
	old, next, source := phpSwitchFixture(t)
	socket := "unix:/run/panel-php-" + core.PHPInstanceID(old) + "/fpm.sock"
	path := siteHealthPath(old)
	cases := map[string]string{
		"foreign marker":           strings.Replace(source, old.ID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
		"foreign pool":             strings.Replace(source, socket, "unix:/run/panel-php-foreign/fpm.sock", 1),
		"dynamic pool":             strings.Replace(source, socket, "$operator_upstream", 1),
		"wrong header":             strings.Replace(source, core.Hash(siteHealthBody(old)), strings.Repeat("a", 64), 1),
		"duplicate health":         strings.Replace(source, "server {", "server { location = "+path+" { return 200 x; }", 1),
		"nested health":            strings.Replace(source, "server {", "server { location /nested { location = "+path+" { return 200 x; } }", 1),
		"quoted health directive":  strings.Replace(source, "location = "+path, "\"location\" = "+path, 1),
		"quoted header directive":  strings.Replace(source, "add_header X-Panel-Config", "\"add_header\" X-Panel-Config", 1),
		"quoted fastcgi directive": strings.Replace(source, "fastcgi_pass "+socket, "\"fastcgi_pass\" "+socket, 1),
		"duplicate names":          strings.Replace(source, "server {", "server { server_name "+old.Domain+";", 1),
		"foreign names":            strings.Replace(source, "server_name "+old.Domain, "server_name foreign.localhost", 1),
		"unterminated block":       source + "server {",
		"oversize":                 source + strings.Repeat(" ", 65536),
		"nul":                      source + "\x00",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := phpSwitchNginxConfig(input, old, next, true); err == nil {
				t.Fatal("ambiguous configuration accepted")
			}
		})
	}
	for _, change := range []func(*core.Site){func(s *core.Site) { s.Settings.Rewrite = "wordpress" }, func(s *core.Site) { s.ID = core.ID() }, func(s *core.Site) { s.Domain = "foreign.localhost" }, func(s *core.Site) { s.PHPVersionID = "" }} {
		candidate := next
		change(&candidate)
		if _, err := phpSwitchNginxConfig(source, old, candidate, true); err == nil {
			t.Fatal("non PHP-only operation accepted")
		}
	}
	old.RuntimeInstanceID = "foreign-instance"
	if _, err := phpSwitchNginxConfig(source, old, next, true); err == nil {
		t.Fatal("foreign instance accepted")
	}
}

func TestPHPSwitchPreviewIsReadOnlyAndApplyRejectsStaleConfigBeforeEffects(t *testing.T) {
	calls := 0
	s := testService(t, func(context.Context, string, ...string) (string, error) {
		calls++
		t.Fatal("preview or stale request executed command")
		return "", nil
	})
	old, next, source := phpSwitchFixture(t)
	path := filepath.Join(s.Config.ConfDir, old.ID+".conf")
	if err := os.WriteFile(path, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	in := core.ApplyRequest{Site: next, PreviousSite: &old, PreserveNginx: true, Enabled: true}
	raw, _ := json.Marshal(in)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/sites/php-preview", strings.NewReader(string(raw))))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var preview struct {
		Protocol, Current, Candidate string
		SHA                          string `json:"config_sha"`
		Preserves                    bool   `json:"preserves_custom_config"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil || preview.Protocol != "php-vhost-switch-v1" || preview.Current != source || preview.SHA != core.Hash(source) || !preview.Preserves || !strings.Contains(preview.Candidate, "autoindex off;") {
		t.Fatal("incorrect preservation preview", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != source || calls != 0 {
		t.Fatal("preview modified configuration")
	}
	in.JobID = core.ID()
	in.ExpectedConfigSHA = core.Hash(source)
	if err := os.WriteFile(path, []byte(source+"# external change\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(context.Background(), in); err == nil || !strings.Contains(err.Error(), "配置已发生变化") {
		t.Fatal("stale preview accepted", err)
	}
	if entries, _ := os.ReadDir(s.Config.SitesDir); len(entries) != 0 {
		t.Fatal("stale preview created site or account")
	}
	if entries, _ := os.ReadDir(s.Config.StateDir); len(entries) != 0 {
		t.Fatal("stale preview wrote executor ledger")
	}
}

func TestPHPSwitchBindingConflictAndBudget(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) {
		t.Fatal("read plan executed command")
		return "", nil
	})
	old, next, source := phpSwitchFixture(t)
	os.WriteFile(filepath.Join(s.Config.ConfDir, old.ID+".conf"), []byte(source), 0644)
	in := core.ApplyRequest{Site: next, PreviousSite: &old, PreserveNginx: true, Enabled: true}
	binding := filepath.Join(s.Config.SystemRoot, "etc/panel/php-sites/bindings", old.ID+".json")
	os.MkdirAll(filepath.Dir(binding), 0700)
	for _, raw := range []string{`{}`, strings.Repeat(" ", 65537)} {
		os.WriteFile(binding, []byte(raw), 0600)
		if _, err := s.phpSwitchPreservationPlan(in); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	raw, _ := json.Marshal(old)
	os.WriteFile(binding, raw, 0600)
	if _, err := s.phpSwitchPreservationPlan(in); err != nil {
		t.Fatal("owned binding rejected", err)
	}
	os.Remove(binding)
	os.Symlink(t.TempDir(), binding)
	if _, err := s.phpSwitchPreservationPlan(in); err == nil {
		t.Fatal("linked binding accepted")
	}
}
