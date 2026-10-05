//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalWAFConfigurePreservesSiteOptOut(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) { return "", nil })
	s.Config.NginxConf = filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(s.Config.NginxConf, []byte("events {}\nhttp {\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	disabled := false
	site := core.Site{ID: core.ID(), Domain: "waf.localhost", Settings: core.DefaultSiteSettings(core.SiteSettings{WAFEnabled: &disabled})}
	config, err := renderSiteConfig(site, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	if err := os.WriteFile(path, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ensureWAFIncludes(); err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != config {
		t.Fatal("global WAF configure reenabled a disabled site", err)
	}
}

func TestRenderWAFUsesFixedValidatedSettings(t *testing.T) {
	httpConfig, serverConfig := renderWAF(map[string]any{"profile": "balanced", "rate_per_second": 20})
	for _, want := range []string{"limit_req_zone", "rate=20r/s", "$panel_waf_bad_args", "sqlmap", "log_format panel_waf escape=json", "\"site\":", "\"rate\":", "$limit_req_status"} {
		if !strings.Contains(httpConfig, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, want := range []string{"return 403", "limit_req zone=panel_waf_per_ip", "limit_req_status 429", "access_log /var/log/nginx/panel-waf.log panel_waf if=$panel_waf_event", "X-Panel-WAF"} {
		if !strings.Contains(serverConfig, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, secret := range []string{"$request_uri\"", "$args\"", "$request_body\"", "$http_cookie\""} {
		if strings.Contains(httpConfig, secret) {
			t.Fatalf("WAF event log exposes request content: %s", secret)
		}
	}
	strict, _ := renderWAF(map[string]any{"profile": "strict", "rate_per_second": 5})
	if !strings.Contains(strict, "zgrab") || !strings.Contains(strict, "rate=5r/s") {
		t.Fatal("strict WAF profile not rendered")
	}
}

func TestWAFEventsBoundedReadAndSymlinkRejection(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) { return "", nil })
	s.Config.SystemRoot = t.TempDir()
	logDir := s.systemPath("/var/log/nginx")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(logDir, "panel-waf.log")
	data := []byte("invalid line\n")
	for i := 0; i < 102; i++ {
		line, err := json.Marshal(core.WAFEvent{Time: "2026-10-04T00:00:00+08:00", Site: "test.local", IP: "127.0.0.1", Status: 403, BadArgs: "1"})
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, append(line, '\n')...)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	page, err := s.wafEvents()
	if err != nil || len(page.Events) != wafEventLimit || !page.HasMore || page.Events[0].BadArgs != "1" {
		t.Fatalf("invalid bounded event result: %+v %v", page, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafEvents(); err == nil {
		t.Fatal("WAF event reader followed a symlink")
	}
}

func TestRenderHardeningAndIntrusion(t *testing.T) {
	baseline := hardeningValues("baseline")
	strict := hardeningValues("strict")
	if baseline["kernel.kptr_restrict"] != "2" || strict["kernel.unprivileged_bpf_disabled"] != "1" {
		t.Fatal("hardening profile mismatch")
	}
	content := renderSysctl(strict)
	if !strings.HasPrefix(content, "# managed by panel") || !strings.Contains(content, "net.ipv4.conf.all.accept_redirects = 0") {
		t.Fatal("sysctl config incomplete")
	}
	jail := renderIntrusion(map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60})
	for _, want := range []string{"[sshd]", "backend = systemd", "maxretry = 5", "findtime = 10m", "bantime = 60m"} {
		if !strings.Contains(jail, want) {
			t.Fatalf("missing %s", want)
		}
	}
}
