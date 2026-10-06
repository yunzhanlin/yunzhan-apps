//go:build linux

package executor

import (
	"bytes"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wafTestNginx(t *testing.T, cfg core.WAFConfig) func(string, string, string, string) int {
	t.Helper()
	bin, e := exec.LookPath("nginx")
	if e != nil {
		t.Skip("real Nginx is not installed")
	}
	root := t.TempDir()
	pub := filepath.Join(root, "public")
	if e = os.Mkdir(pub, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(pub, "index.html"), []byte("safe site"), 0644); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	h, s := renderWAFPolicy(cfg)
	h = strings.ReplaceAll(h, "listen 127.0.0.1:19101;", fmt.Sprintf("listen 127.0.0.1:%d;", port))
	s = strings.ReplaceAll(s, "/var/log/nginx/panel-waf.log", filepath.Join(root, "waf.log"))
	servers := ""
	for i, host := range []string{"a.localhost", "b.localhost"} {
		id := strings.Repeat(string(rune('a'+i)), 32)
		servers += fmt.Sprintf("server { listen 127.0.0.1:%d; server_name %s; set $panel_waf_site %s; %s root %s; location / { try_files $uri /index.html; } location = /__panel_health_%s { return 200 healthy; } }\n", port, host, id, s, wafQuote(pub), id)
	}
	conf := fmt.Sprintf("master_process off; daemon off; pid %s; error_log %s notice; events {worker_connections 64;} http { access_log off; %s %s }", filepath.Join(root, "nginx.pid"), filepath.Join(root, "error.log"), h, servers)
	path := filepath.Join(root, "nginx.conf")
	if e = os.WriteFile(path, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command(bin, "-t", "-p", root, "-c", path).CombinedOutput(); e != nil {
		t.Fatalf("real nginx -t: %s %v", out, e)
	}
	var output bytes.Buffer
	cmd := exec.Command(bin, "-p", root, "-c", path)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	address := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("nginx did not listen: %s", output.String())
	}
	client := &http.Client{Timeout: time.Second}
	return func(host, path, agent, cookie string) int {
		t.Helper()
		r, e := http.NewRequest("GET", "http://"+address+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Host = host
		r.Header.Set("User-Agent", agent)
		r.Header.Set("Cookie", cookie)
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
}

func TestWAFRealNginxMetadataAndScope(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.Policy.CCEnabled = false
	cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: strings.Repeat("b", 32), Mode: "observe"}}
	request := wafTestNginx(t, cfg)
	for _, x := range []struct {
		host, path, agent, cookie string
		want                      int
	}{
		{"a.localhost", "/", "Browser", "", 200},
		{"panel-waf-check.invalid", "/__panel_waf_check", "Browser", "", 200},
		{"a.localhost", "/?q=union%20select", "Browser", "", 403},
		{"a.localhost", "/?q=%3Cscript%3E", "Browser", "", 403},
		{"a.localhost", "/", "sqlmap", "", 403},
		{"b.localhost", "/", "sqlmap", "", 200},
		{"a.localhost", "/__panel_health_" + strings.Repeat("a", 32), "sqlmap", "", 200},
	} {
		if got := request(x.host, x.path, x.agent, x.cookie); got != x.want {
			t.Errorf("%s %s %s => %d want %d", x.host, x.path, x.agent, got, x.want)
		}
	}
}

func TestWAFRealNginxLiteralRulesAndLists(t *testing.T) {
	cfg := core.DefaultWAFConfig()
	cfg.Policy.CCEnabled = false
	cfg.Policy.Lists["url_deny"] = []core.WAFEntry{{Value: "/private", SiteID: strings.Repeat("a", 32)}}
	cfg.Policy.Rules = []core.WAFRule{{ID: strings.Repeat("c", 32), Name: "literal", Field: "user_agent", Operator: "exact", Value: `quoted $value;" \\`, Action: "block", Enabled: true}, {ID: strings.Repeat("d", 32), Name: "audit", Field: "uri", Operator: "exact", Value: "/audit", Action: "observe", Enabled: true}}
	request := wafTestNginx(t, cfg)
	for _, x := range []struct {
		host, path, agent string
		want              int
	}{{"a.localhost", "/private/file", "Browser", 403}, {"b.localhost", "/private/file", "Browser", 200}, {"a.localhost", "/audit", "Browser", 200}, {"a.localhost", "/", `quoted $value;" \\`, 403}} {
		if got := request(x.host, x.path, x.agent, ""); got != x.want {
			t.Errorf("%s %s => %d want %d", x.host, x.path, got, x.want)
		}
	}
}

func TestWAFRealNginxAllowPrecedenceAndURLCC(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		cfg := core.DefaultWAFConfig()
		cfg.Policy.Lists["ip_allow"] = []core.WAFEntry{{Value: "127.0.0.1/32"}}
		cfg.Policy.Lists["ip_deny"] = []core.WAFEntry{{Value: "127.0.0.0/24"}}
		request := wafTestNginx(t, cfg)
		if got := request("a.localhost", "/", "sqlmap", ""); got != 200 {
			t.Fatal("IP allow must beat IP deny and scanner", got)
		}
	})
	t.Run("cc", func(t *testing.T) {
		cfg := core.DefaultWAFConfig()
		cfg.Rate = 200
		cfg.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("e", 32), Path: "/login", Rate: 1, Burst: 1, Enabled: true}}
		off := false
		cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: strings.Repeat("b", 32), Mode: "inherit", CCEnabled: &off}}
		request := wafTestNginx(t, cfg)
		blocked := false
		for i := 0; i < 8; i++ {
			if request("a.localhost", "/login", "Browser", "") == 429 {
				blocked = true
			}
			if got := request("b.localhost", "/login", "Browser", ""); got != 200 {
				t.Fatal("site CC opt-out not respected", got)
			}
		}
		if !blocked {
			t.Fatal("URL CC did not block burst")
		}
	})
}
