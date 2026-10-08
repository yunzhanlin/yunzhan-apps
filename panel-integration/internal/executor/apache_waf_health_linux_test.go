//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestApacheWAFHealthRejectsRunningButUnloadedOrWrongFingerprint(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	for _, tc := range []struct {
		name, header string
		status       int
		failure      bool
	}{
		{"correct", apacheWAFProbe(cfg), 404, false},
		{"blocked-but-loaded", apacheWAFProbe(cfg), 403, false},
		{"missing-header", "", 200, true},
		{"stale-revision", core.ApacheWAFVersion + ":wrong", 200, true},
		{"server-failure", apacheWAFProbe(cfg), 503, true},
		{"redirect-not-proof", apacheWAFProbe(cfg), 302, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: siteTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "HEAD" || r.URL.String() != "http://127.0.0.1:19080/__yunzhan_waf_probe" || r.Host != "owned.localhost" || r.Header.Get("Cookie") != "" {
					t.Fatal("probe left fixed loopback or forwarded secrets", r)
				}
				h := make(http.Header)
				h.Set("X-Panel-Apache-WAF", tc.header)
				return &http.Response{StatusCode: tc.status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})}
			if err := apacheWAFProbeLoaded(context.Background(), cfg, "owned.localhost", client); (err != nil) != tc.failure {
				t.Fatal("false healthy fingerprint", err)
			}
		})
	}
	client := &http.Client{Transport: siteTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	if apacheWAFProbeLoaded(context.Background(), cfg, "owned.localhost", client) == nil {
		t.Fatal("unreachable server became healthy")
	}
}

func TestApacheWAFHealthExactFilesAndAllHostMounts(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	id, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	host := func(id, domain string) string {
		return "<VirtualHost 127.0.0.1:19080>\n ServerName " + domain + "\n SetEnvIfExpr \"true\" PANEL_AW_SITE=" + id + "\n " + apacheWAFInclude + " CustomLog /var/log/apache2/panel-" + id + ".access.log combined\n</VirtualHost>\n"
	}
	source := "# managed by panel\n" + host(id, "first.localhost") + host(second, "second.localhost")
	bindings, err := apacheWAFBindings(source)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := renderApacheWAF(cfg, bindings)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	if domain, err := apacheWAFConfigurationFilesMatch(source, cfg, "/missing/module.so", path); err != nil || domain != "first.localhost" {
		t.Fatal("valid default-off exact files rejected", domain, err)
	}
	for _, changed := range []string{
		strings.Replace(source, " "+apacheWAFInclude, "", 1),
		strings.Replace(source, host(second, "second.localhost"), strings.Replace(host(second, "second.localhost"), " "+apacheWAFInclude, "", 1), 1),
		strings.Replace(source, " "+apacheWAFInclude, " "+apacheWAFInclude+" "+apacheWAFInclude, 1),
		strings.Replace(source, `SetEnvIfExpr "true" PANEL_AW_SITE=`+id, `SetEnvIfExpr "true" PANEL_AW_SITE=`+second, 1),
		source + "RemoteIPHeader X-Forwarded-For\n",
		source + "IncludeOptional /tmp/foreign.conf\n",
	} {
		if _, err := apacheWAFConfigurationFilesMatch(changed, cfg, "/missing/module.so", path); err == nil {
			t.Fatal("changed host or trust claimed healthy", changed)
		}
	}
	if err := os.WriteFile(path, []byte(rules+"# drift\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := apacheWAFConfigurationFilesMatch(source, cfg, "/missing/module.so", path); err == nil {
		t.Fatal("changed rules claimed healthy")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := apacheWAFConfigurationFilesMatch(source, cfg, "/missing/module.so", path); err == nil {
		t.Fatal("linked rules claimed healthy")
	}
}

func TestApacheWAFStableReadRejectsSymlinkFIFOAndOversize(t *testing.T) {
	root := t.TempDir()
	ordinary := filepath.Join(root, "ordinary")
	if err := os.WriteFile(ordinary, []byte("exact"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := apacheWAFReadStableFile(ordinary, 5); err != nil || string(data) != "exact" {
		t.Fatal(string(data), err)
	}
	if _, err := apacheWAFReadStableFile(ordinary, 4); err == nil {
		t.Fatal("oversize accepted")
	}
	linked, fifo := filepath.Join(root, "linked"), filepath.Join(root, "fifo")
	if err := os.Symlink(ordinary, linked); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, linked, fifo} {
		if _, err := apacheWAFReadStableFile(path, 100); err == nil {
			t.Fatal("unsafe type accepted", path)
		}
	}
}

func TestApacheWAFHealthRejectsUnmanagedOrChangedFilesReadOnly(t *testing.T) {
	s := wafPolicyFixture(t)
	cfg := core.DefaultApacheWAFConfig()
	if _, err := s.apacheWAFConfigurationMatches("2.0.0", cfg); err == nil {
		t.Fatal("legacy version claimed new integrity")
	}
	if _, err := s.apacheWAFConfigurationMatches(core.ApacheWAFVersion, cfg); err == nil {
		t.Fatal("absent source claimed loaded")
	}
	s.Config.ApacheSiteConfig = filepath.Join(t.TempDir(), "apache.conf")
	if err := os.WriteFile(s.Config.ApacheSiteConfig, []byte("# unmanaged\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Config.ApacheSiteConfig)
	if _, err := s.apacheWAFConfigurationMatches(core.ApacheWAFVersion, cfg); err == nil {
		t.Fatal("foreign source became healthy")
	}
	if after, _ := os.ReadFile(s.Config.ApacheSiteConfig); string(before) != string(after) {
		t.Fatal("health check mutated source")
	}
	if _, err := os.Stat(s.moduleDir("apache-waf")); !os.IsNotExist(err) {
		t.Fatal("health check created module state", err)
	}
}
