//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestSiteLoadBalanceBindingPreservesSiteAndPool(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	ctx := context.Background()
	if err := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{
		"id": "load-balance", "version": "1.8.5", "settings": map[string]any{}, "installed_at": core.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleInstalledRecord("load-balance"); err != nil {
		t.Fatal("legacy application fixture admission failed", err)
	}
	lbSave(t, s, in)
	site := core.Site{ID: core.ID(), Domain: in.Domain, Settings: core.SiteSettings{
		Mode: "proxy", ProxyURL: "http://127.0.0.1:19777", PublicIngress: true, LoadBalanceDomain: in.Domain,
	}}
	public := t.TempDir()
	if err := s.checkDomainOwners(site); err != nil {
		t.Fatal("the managed pool is on a different listener", err)
	}
	rendered, err := s.renderManagedSiteConfig(ctx, site, public, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"proxy_pass http://panel_lb_" + loadBalanceID(in.Domain) + ";", "listen 0.0.0.0:80;",
		"proxy_set_header X-Forwarded-For $remote_addr;", "proxy_set_header Forwarded \"\";",
		siteLoadBalanceMarker(in.Domain), siteHealthPath(site),
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatal("missing", expected)
		}
	}
	if strings.Contains(rendered, site.Settings.ProxyURL) || strings.Contains(rendered, "$proxy_add_x_forwarded_for") {
		t.Fatal("bound business traffic was re-proxied or forwarded unsanitized")
	}
	path := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	for _, contents := range []string{rendered, disabledSiteConfig(site)} {
		if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
		before := lbFiles(t, s, in.Domain)
		remove := core.AppModuleInput{Domain: in.Domain, ExpectedRevision: 1}
		if _, err := s.moduleLoadBalance(ctx, "remove", remove); err == nil || !strings.Contains(err.Error(), "仍有网站绑定") {
			t.Fatal("bound pool removal did not fail", err)
		}
		lbAssertFiles(t, s, in.Domain, before)
	}
	site.Settings.LoadBalanceDomain = ""
	restored, err := s.renderManagedSiteConfig(ctx, site, public, true)
	if err != nil || !strings.Contains(restored, site.Settings.ProxyURL) || strings.Contains(restored, siteLoadBalancePrefix) {
		t.Fatal("original service mode did not return", err)
	}
	if err := os.WriteFile(path, []byte(restored), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleLoadBalance(ctx, "remove", core.AppModuleInput{Domain: in.Domain, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestSiteLoadBalanceRejectsUnsafeOrMissingPool(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	ctx := context.Background()
	entry := loadBalanceEntry{Domain: in.Domain, Port: in.Port, Format: 1, Revision: 1, Nodes: in.Nodes}
	for _, address := range []string{"127.0.0.2:19101", "127.0.0.1:80", "[::1]:443", "127.0.0.1:44000"} {
		entry.Nodes[0].Address = address
		if validateWebsiteBalanceNodes(entry, []loadBalanceEntry{{Port: 44000}}) == nil {
			t.Fatal("bound upstream can still reach a local panel listener", address)
		}
	}
	site := core.Site{ID: core.ID(), Domain: "site.example.test", Settings: core.SiteSettings{LoadBalanceDomain: in.Domain}}
	if _, err := s.renderManagedSiteConfig(ctx, site, t.TempDir(), false); err == nil {
		t.Fatal("stopped site stored an unverified binding")
	}
	mux := http.NewServeMux()
	s.siteLoadBalanceRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/v1/sites/load-balancers", nil))
	if response.Code != http.StatusOK || response.Body.String() != "{\"installed\":false,\"entries\":[]}\n" {
		t.Fatal(response.Code, response.Body.String())
	}
}

func TestSiteLoadBalanceKeepsBackendTLSContract(t *testing.T) {
	s := wafPolicyFixture(t)
	in := lbFixtureInput()
	site := core.Site{ID: core.ID(), Domain: "site.example.test", Settings: core.SiteSettings{LoadBalanceDomain: in.Domain}}
	entry := loadBalanceEntry{Domain: in.Domain, BackendTLS: &core.LoadBalanceBackendTLS{ServerName: "origin.example.test"}}
	rendered, err := renderSiteConfigWithUpstream(site, t.TempDir(), s.renderSiteLoadBalanceProxy(entry))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"proxy_pass https://panel_lb_", "proxy_ssl_verify on;", "proxy_ssl_name origin.example.test;", "proxy_set_header Host origin.example.test;", s.loadBalanceCAPath(in.Domain)} {
		if !strings.Contains(rendered, expected) {
			t.Fatal("missing", expected)
		}
	}
}

func TestSiteLoadBalancePreviewRejectsDriftAndChangedCandidate(t *testing.T) {
	s := wafPolicyFixture(t)
	ctx := context.Background()
	in := lbFixtureInput()
	if err := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{
		"id": "load-balance", "version": "1.8.5", "settings": map[string]any{}, "installed_at": core.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleInstalledRecord("load-balance"); err != nil {
		t.Fatal("legacy application fixture admission failed", err)
	}
	lbSave(t, s, in)
	site := core.Site{ID: core.ID(), Name: "Binding test", Slug: "binding-test", Domain: "site.example.test", Status: "running"}
	// The fixture records a real original render and adds a manual directive.
	public := filepath.Join(s.Config.SitesDir, site.ID, "public")
	if err := os.MkdirAll(public, 0755); err != nil {
		t.Fatal(err)
	}
	previous, err := renderSiteConfig(site, public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	write := func(contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	next := site
	next.Settings.LoadBalanceDomain = in.Domain
	input := core.ApplyRequest{Site: next, PreviousBindingSite: &site, Enabled: true}
	mux := http.NewServeMux()
	s.siteSettingsRoutes(mux)
	preview := func() *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("POST", "/v1/sites/preview?binding=1", strings.NewReader(string(data))))
		return response
	}
	custom := strings.Replace(previous, "  disable_symlinks on;", "  add_header X-Custom-Test kept;\n  disable_symlinks on;", 1)
	write(custom)
	if response := preview(); response.Code != 409 || !strings.Contains(response.Body.String(), "自定义配置") {
		t.Fatal(response.Code, response.Body.String())
	}
	write(previous)
	response := preview()
	var out struct {
		CurrentSHA   string `json:"config_sha"`
		CandidateSHA string `json:"candidate_sha"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &out) != nil || out.CurrentSHA != core.Hash(previous) || len(out.CandidateSHA) != 64 {
		t.Fatal(response.Code, response.Body.String())
	}
	input.JobID = core.ID()
	input.ExpectedConfigSHA = out.CurrentSHA
	input.ExpectedCandidateSHA = core.Hash("other-candidate")
	result, err := s.Apply(ctx, input)
	if err == nil || !strings.Contains(err.Error(), "候选分流配置已变化") || !result.Restored {
		t.Fatal(result, err)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != previous {
		t.Fatal("stale candidate changed original configuration", err)
	}
	if _, err := os.Lstat(filepath.Join(s.Config.StateDir, "backups", input.JobID+".conf")); !os.IsNotExist(err) {
		t.Fatal("failed digest check entered the mutation transaction", err)
	}
}

func TestSiteLoadBalancePrivateNginx(t *testing.T) {
	nginx := os.Getenv("PANEL_SITE_LB_PRIVATE_NGINX")
	if nginx == "" {
		t.Skip("isolated Nginx binary required")
	}
	if !filepath.IsAbs(nginx) {
		t.Fatal("Nginx binary must be explicitly identified")
	}
	stage := t.TempDir()
	if err := os.Chmod(filepath.Dir(stage), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stage, 0755); err != nil {
		t.Fatal(err)
	}
	type witness struct {
		Backend, Method, URI, Body, Host, RealIP, ForwardedFor, ForwardedHost, Forwarded, Proto, Port string
	}
	start := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err != nil {
				http.Error(w, "fixture read failed", http.StatusBadRequest)
				return
			}
			w.Header().Set("X-Panel-Config", "spoofed-by-upstream")
			_ = json.NewEncoder(w).Encode(witness{
				Backend: name, Method: r.Method, URI: r.RequestURI, Body: string(body), Host: r.Host,
				RealIP: r.Header.Get("X-Real-IP"), ForwardedFor: r.Header.Get("X-Forwarded-For"),
				ForwardedHost: r.Header.Get("X-Forwarded-Host"), Forwarded: r.Header.Get("Forwarded"),
				Proto: r.Header.Get("X-Forwarded-Proto"), Port: r.Header.Get("X-Forwarded-Port"),
			})
		}))
	}
	first, second, original := start("first"), start("second"), start("original")
	defer first.Close()
	defer second.Close()
	defer original.Close()
	nextPort := func() int {
		t.Helper()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		if port < 20000 || port > 60000 {
			return 0
		}
		return port
	}
	sitePort, poolPort := nextPort(), nextPort()
	for sitePort == 0 {
		sitePort = nextPort()
	}
	for poolPort == 0 || poolPort == sitePort {
		poolPort = nextPort()
	}
	entry := loadBalanceEntry{
		Domain: "app.example.test", Format: 1, Revision: 1, Port: poolPort, Sticky: true,
		Nodes: []core.AppUpstream{{Address: strings.TrimPrefix(first.URL, "http://"), Weight: 1}, {Address: strings.TrimPrefix(second.URL, "http://"), Weight: 1}},
	}
	pool, err := renderLoadBalanceEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	waf := false
	initial := core.Site{ID: core.ID(), Domain: entry.Domain, Settings: core.SiteSettings{Mode: "proxy", ProxyURL: original.URL, WAFEnabled: &waf}}
	bound := initial
	bound.Settings.LoadBalanceDomain = entry.Domain
	executor := wafPolicyFixture(t)
	render := func(site core.Site, upstream string) string {
		t.Helper()
		c, err := renderSiteConfigWithUpstream(site, stage, upstream)
		if err != nil {
			t.Fatal(err)
		}
		c = strings.Replace(c, "listen 127.0.0.1:19101;", fmt.Sprintf("listen 127.0.0.1:%d;", sitePort), 1)
		return strings.ReplaceAll(c, "/var/log/nginx/", stage+"/")
	}
	conf := filepath.Join(stage, "nginx.conf")
	pid := filepath.Join(stage, "nginx.pid")
	writeConfig := func(content string) {
		t.Helper()
		settings := fmt.Sprintf("worker_processes 1;\npid %s;\nerror_log %s notice;\nevents { worker_connections 128; }\nhttp {\n", pid, filepath.Join(stage, "error.log"))
		if os.Geteuid() == 0 {
			settings = "user nobody nogroup;\n" + settings
		}
		for _, component := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
			settings += fmt.Sprintf("%s_temp_path %s;\n", component, filepath.Join(stage, component))
		}
		settings += "log_format panel_site '$request';\naccess_log off;\nmap $http_upgrade $panel_connection_upgrade { default upgrade; '' close; }\n" +
			fmt.Sprintf("server { listen 127.0.0.1:%d default_server; server_name _; return 404; }\n", sitePort)
		if err := os.WriteFile(conf, []byte(settings+pool+content+"}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(nginx, "-t", "-p", stage+"/", "-c", conf).CombinedOutput(); err != nil {
			t.Fatalf("private nginx -t: %v %s", err, output)
		}
	}
	writeConfig(render(bound, executor.renderSiteLoadBalanceProxy(entry)))
	process := exec.Command(nginx, "-p", stage+"/", "-c", conf, "-g", "daemon off;")
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	defer func() {
		_ = process.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = process.Process.Kill()
			<-done
			t.Error("private Nginx did not stop")
		}
	}()
	send := func(source, method, uri, body string) (int, witness, string, error) {
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		url := fmt.Sprintf("http://127.0.0.1:%d%s", sitePort, uri)
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			return 0, witness{}, "", err
		}
		req.Host = entry.Domain
		req.Header.Set("X-Real-IP", "203.0.113.44")
		req.Header.Set("X-Forwarded-For", "203.0.113.45")
		req.Header.Set("X-Forwarded-Host", "spoof.example.test")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Port", "443")
		req.Header.Set("Forwarded", "for=203.0.113.46")
		response, err := client.Do(req)
		if err != nil {
			return 0, witness{}, "", err
		}
		defer response.Body.Close()
		var record witness
		if response.StatusCode == 200 {
			err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&record)
		}
		return response.StatusCode, record, response.Header.Get("X-Panel-Config"), err
	}
	await := func(source string, predicate func(int, witness, string) bool) witness {
		t.Helper()
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
			status, record, header, err := send(source, "GET", "/health", "")
			if err == nil && predicate(status, record, header) {
				return record
			}
			time.Sleep(50 * time.Millisecond)
		}
		b, _ := os.ReadFile(filepath.Join(stage, "error.log"))
		t.Fatalf("Nginx did not reach expected journey phase: %s", b)
		return witness{}
	}
	source := "127.0.1.9"
	base := await(source, func(status int, record witness, header string) bool {
		return status == 200 && record.Backend != "" && header == core.Hash(siteHealthBody(bound))
	})
	for i := 0; i < 4; i++ {
		status, record, header, err := send(source, "POST", "/path%2Fpart?q=%23x", "preserved input")
		if err != nil || status != 200 || header != core.Hash(siteHealthBody(bound)) ||
			record != (witness{base.Backend, "POST", "/path%2Fpart?q=%23x", "preserved input", entry.Domain, source, source, entry.Domain, "", "http", strconv.Itoa(sitePort)}) {
			t.Fatal("site proxy changed the business request or trusted spoofed headers", status, record, header, err)
		}
	}
	separate := false
	for i := 2; i < 24; i++ {
		peer := fmt.Sprintf("127.0.%d.9", i)
		status, record, _, err := send(peer, "GET", "/peer", "")
		if err != nil || status != 200 || record.RealIP != peer {
			t.Fatal(status, record, err)
		}
		separate = separate || record.Backend != base.Backend
	}
	if !separate {
		t.Fatal("distinct effective client addresses never hit different backends")
	}
	if base.Backend == "first" {
		first.Close()
	} else {
		second.Close()
	}
	await(source, func(status int, record witness, _ string) bool {
		return status == 200 && record.Backend != "" && record.Backend != base.Backend
	})
	writeConfig(disabledSiteConfig(bound))
	if err = process.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	await(source, func(status int, _ witness, _ string) bool { return status == 404 })
	writeConfig(render(initial, ""))
	if err = process.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	await(source, func(status int, record witness, header string) bool {
		return status == 200 && record.Backend == "original" && header == core.Hash(siteHealthBody(initial))
	})
	t.Log("original business proxy restored after sticky client routing, spoofed header stripping, backend failure and site stop")
}
