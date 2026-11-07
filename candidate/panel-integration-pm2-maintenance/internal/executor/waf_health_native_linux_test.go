//go:build linux

package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// ACTUAL isolated Nginx requests with the production versioned renderer.
// Data CIDRs are synthetic and ONLY the exact data/log prefixes + dedicated
// 19101 probe are relocated/omitted for isolation. This does NOT prove provider
// signatures, normal WAF installation or country cache activation authority.
func TestWAFBoundHealthNativeTraffic(t *testing.T) {
	scope := os.Getenv("PANEL_QA_WAF_TRAFFIC_NATIVE")
	if scope == "" {
		t.Skip("explicit owned isolated native Nginx traffic scope required")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/waf-traffic24biij-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(scope) {
		t.Fatal("unqualified native traffic scope")
	}
	if err := statisticsGeoParents(scope); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(scope)
	if err != nil || !moduleRecordInfo(info, true, false) {
		t.Fatal("native scope not private Root directory", err)
	}
	raw, err := exec.Command("/usr/bin/systemctl", "show", "nginx.service", "--property=MainPID", "--value").Output()
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || perr != nil || pid < 2 {
		t.Fatal("installed Nginx identity unavailable", err)
	}
	nginx := "/proc/" + strconv.Itoa(pid) + "/exe"
	f, err := os.Open(nginx)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := f.Stat()
	f.Close()
	if err != nil || !binary.Mode().IsRegular() || binary.Size() < 1 || binary.Size() > 256<<20 {
		t.Fatal("installed Nginx executable identity invalid")
	}
	const ownSite = "11111111111111111111111111111111"
	const otherSite = "99999999999999999999999999999999"
	base := core.DefaultWAFConfig()
	base.Rate = 200
	base.Policy.CCEnabled = false
	base.Policy.Burst = 1000
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	count := 0
	start := func(cfg core.WAFConfig, version, phase string, bindings map[string]string, untrusted map[string]bool) (string, func()) {
		t.Helper()
		dir := filepath.Join(scope, phase)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		httpPart, serverPart := renderWAFPolicyVersion(cfg, version)
		lines := strings.Split(httpPart, "\n")
		probe := 0
		kept := []string{}
		for _, line := range lines {
			if strings.HasPrefix(line, "server { listen 127.0.0.1:19101; server_name panel-waf-check.invalid;") {
				if !strings.Contains(line, wafQuote(wafProbeValueVersion(cfg, version))) {
					t.Fatal("unknown generated probe")
				}
				probe++
				continue
			}
			kept = append(kept, line)
		}
		if probe != 1 {
			t.Fatal("exact generated dedicated probe missing")
		}
		httpPart = strings.Join(kept, "\n")
		if strings.Count(serverPart, "/var/log/nginx/panel-waf.log") != 1 {
			t.Fatal("unknown generated log source")
		}
		serverPart = strings.ReplaceAll(serverPart, "/var/log/nginx/panel-waf.log", filepath.Join(dir, "security.log"))
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		var conf strings.Builder
		fmt.Fprintf(&conf, "daemon off;\nmaster_process on;\npid %s;\nerror_log %s warn;\nevents { worker_connections 64; }\nhttp { access_log off; client_body_temp_path %s; proxy_temp_path %s; fastcgi_temp_path %s; uwsgi_temp_path %s; scgi_temp_path %s;\n%s\n", filepath.Join(dir, "nginx.pid"), filepath.Join(dir, "error.log"), filepath.Join(dir, "client"), filepath.Join(dir, "proxy"), filepath.Join(dir, "fastcgi"), filepath.Join(dir, "uwsgi"), filepath.Join(dir, "scgi"), httpPart)
		for name, id := range bindings {
			rules := serverPart
			if untrusted[name] {
				prefix := renderWAFTrustedProxy(cfg.TrustedProxy)
				if !strings.Contains(rules, prefix) || prefix == "" {
					t.Fatal("untrusted fixture source invalid")
				}
				rules = strings.Replace(rules, prefix, "", 1)
			}
			fmt.Fprintf(&conf, "server { listen 127.0.0.1:%d; server_name %s; set $panel_waf_site %s;\n%s\nlocation = /__panel_health_%s { return 200 'private health'; }\nlocation / { return 200 'private application response'; }\n}\n", port, name, wafQuote(id), rules, id)
		}
		conf.WriteString("}\n")
		config := filepath.Join(dir, "nginx.conf")
		if err := os.WriteFile(config, []byte(conf.String()), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		pre := exec.CommandContext(ctx, nginx, "-t", "-p", dir+"/", "-c", config, "-e", filepath.Join(dir, "startup.log"))
		out, e := pre.CombinedOutput()
		if e != nil {
			cancel()
			t.Fatal("isolated actual Nginx syntax rejected", e, string(out))
		}
		output, e := os.OpenFile(filepath.Join(dir, "process.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, nginx, "-p", dir+"/", "-c", config, "-e", filepath.Join(dir, "startup.log"))
		cmd.Stdout, cmd.Stderr = output, output
		cmd.WaitDelay = time.Second
		if e := cmd.Start(); e != nil {
			cancel()
			output.Close()
			t.Fatal(e)
		}
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()
		done := false
		stop := func() {
			if done {
				return
			}
			done = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-wait:
			case <-time.After(2 * time.Second):
				cancel()
				<-wait
			}
			cancel()
			output.Close()
		}
		t.Cleanup(stop)
		origin := "http://127.0.0.1:" + strconv.Itoa(port)
		ready := false
		for i := 0; i < 100; i++ {
			conn, e := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 30*time.Millisecond)
			if e == nil {
				conn.Close()
				ready = true
				break
			}
			select {
			case e := <-wait:
				done = true
				cancel()
				output.Close()
				t.Fatal("isolated Nginx ended before listener", e)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			stop()
			t.Fatal("isolated Nginx listener unavailable")
		}
		return origin, stop
	}
	visit := func(origin, host, path, ip, agent string, want int) {
		t.Helper()
		r, e := http.NewRequest("GET", origin+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Host = host
		r.Header.Set("User-Agent", "Private country traffic QA")
		if ip != "" {
			r.Header.Set("X-Forwarded-For", ip)
		}
		if agent != "" {
			r.Header.Set("User-Agent", agent)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		_, e = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if e != nil || response.StatusCode != want {
			t.Fatalf("private native case host=%s path=%s ip=%s got=%d want=%d err=%v", host, path, ip, response.StatusCode, want, e)
		}
		count++
	}
	old, stop := start(base, "2.5.1", "original-vulnerable", map[string]string{"old-health.invalid": ownSite}, nil)
	visit(old, "old-health.invalid", "/?q=union%20select", "", "", 403)
	visit(old, "old-health.invalid", "/__panel_health_"+otherSite+"?q=union%20select", "", "", 200)
	visit(old, "old-health.invalid", "/__panel_health_"+ownSite+"?q=union%20select", "", "", 200)
	stop()
	fixed, stop := start(base, "2.5.2", "fixed-health", map[string]string{"fixed-health.invalid": ownSite}, nil)
	visit(fixed, "fixed-health.invalid", "/?q=union%20select", "", "", 403)
	visit(fixed, "fixed-health.invalid", "/__panel_health_"+otherSite+"?q=union%20select", "", "", 403)
	visit(fixed, "fixed-health.invalid", "/__panel_health_"+ownSite+"?q=union%20select", "", "", 200)
	stop()
	t.Logf("actual_private_HTTP_cases=%d old2.5.1_cross_site_health_bypass_reproduced=true current2.5.2_site_bound_health_fix_verified=true normal_signed_install_acceptance=false", count)
}
