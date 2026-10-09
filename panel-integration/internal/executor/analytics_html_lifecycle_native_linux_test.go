//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These bindings exist only in the fixture's already unshared mount/network
// namespaces. The host root is read-only; no original service is signaled.
func analyticsHTMLPrivateCanonicalMounts(t *testing.T, base string) {
	t.Helper()
	for _, kind := range []string{"mnt", "net"} {
		self, e := os.Readlink("/proc/self/ns/" + kind)
		init, e2 := os.Readlink("/proc/1/ns/" + kind)
		if e != nil || e2 != nil || self == init {
			t.Fatal("canonical fixture requires an unshared namespace", kind, e, e2)
		}
	}
	var fs syscall.Statfs_t
	if os.Getenv("PANEL_QA_ANALYTICS_NATIVE") != "1" || os.Geteuid() != 0 || syscall.Statfs("/", &fs) != nil || fs.Flags&1 == 0 || !strings.HasPrefix(base, "/tmp/analytics-native-") {
		t.Fatal("canonical fixture requires the explicit private read-only-root boundary")
	}
	resources := map[string][]byte{}
	for _, name := range []string{"fastcgi_params", "mime.types"} {
		data, e := os.ReadFile("/etc/nginx/" + name)
		if e != nil || len(data) > 64<<10 {
			t.Fatal("actual Nginx standard resource", name, e)
		}
		resources[name] = data
	}
	for index, target := range []string{"/etc/nginx", "/etc/panel", "/var/lib/panel-executor", "/opt/panel/app-modules", "/srv/panel/sites", "/var/log/nginx", "/run"} {
		st, err := os.Lstat(target)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			t.Fatal("canonical target must already exist and never be created on host", target, err)
		}
		source := filepath.Join(base, fmt.Sprintf("private-canonical-%d", index))
		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
			t.Fatal("private bind", target, err)
		}
		bound := target
		t.Cleanup(func() {
			if err := syscall.Unmount(bound, 0); err != nil {
				t.Error("private fixture unmount failed; original root still read-only", bound, err)
			}
		})
	}
	for name, data := range resources {
		if err := os.WriteFile("/etc/nginx/"+name, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func analyticsHTMLNativeGlobalLifecycle(t *testing.T, ctx context.Context, base, compiled, nginx, version string) {
	t.Helper()
	analyticsHTMLPrivateCanonicalMounts(t, base)
	for _, path := range []string{"/run/panel-nginx", "/etc/panel/sites-enabled", analyticsHTMLNativeRoot, analyticsHTMLBuilds} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(analyticsHTMLBuilds, 0700); err != nil {
		t.Fatal(err)
	}
	id, nextID := strings.Repeat("b", 32), strings.Repeat("c", 32)
	var first analyticsHTMLBuildRecord
	for _, jobID := range []string{id, nextID} {
		prefix := filepath.Join(analyticsHTMLNativeRoot, jobID)
		if err := publishAnalyticsHTMLProgram(ctx, compiled, prefix); err != nil {
			t.Fatal("actual program publication", err)
		}
		if err := publishAnalyticsHTMLSharedProgram(ctx, prefix); err != nil {
			t.Fatal("actual shared program publication", err)
		}
		record := analyticsHTMLBuildRecord{analyticsHTMLEngineIdentity: analyticsHTMLEngineIdentity{Format: 1, JobID: jobID, State: "ready", Architecture: runtime.GOARCH, Prefix: prefix, ProgramSHA: analyticsHTMLProgramSHA, NginxBinary: nginx}, NginxVersion: version, PatchSourceSHA: analyticsNJSHeaderSourceSHA, SourceSHA: map[string]string{}, StartedAt: core.Now(), FinishedAt: core.Now(), Steps: []core.Step{{Time: core.Now(), Message: "private fixture: actual compiled ABI/program copied and verified; not the production build unit"}}, ABIValidated: true}
		sources, _ := analyticsHTMLSources(version)
		for _, source := range sources {
			record.SourceSHA[source.Name] = source.SHA256
		}
		var err error
		if record.NginxSHA, err = analyticsHTMLFileSHA(ctx, nginx, 32<<20); err != nil {
			t.Fatal(err)
		}
		if record.ModuleSHA, err = analyticsHTMLFileSHA(ctx, filepath.Join(prefix, "ngx_http_js_module.so"), 32<<20); err != nil {
			t.Fatal(err)
		}
		if record.TreeSHA, err = runtimeTreeSHA(ctx, prefix, prefix); err != nil {
			t.Fatal(err)
		}
		if err := createAnalyticsHTMLPrivateJSON(filepath.Join(analyticsHTMLBuilds, jobID+".json"), record); err != nil {
			t.Fatal(err)
		}
		if jobID == id {
			first = record
		}
	}
	store, err := core.OpenStore(filepath.Join(base, "private-collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	for _, slug := range []string{"native-static", "native-php"} {
		if _, err := store.CreateSiteAtDomain("Private real analytics", slug, slug+".example.test", core.ID(), "private QA"); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(base, "private-panel-data"), filepath.Join(base, "private-web")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	panel, err := core.NewServer(store, core.Config{DataDir: filepath.Join(base, "private-panel-data"), WebDir: filepath.Join(base, "private-web"), Origin: "http://127.0.0.1:19100", Listen: "127.0.0.1:19100", Socket: filepath.Join(base, "no-management-socket")})
	if err != nil {
		t.Fatal(err)
	}
	var incoming sync.Mutex
	collectorHeadersClean := true
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		incoming.Lock()
		collectorHeadersClean = collectorHeadersClean && r.Header.Get("Cookie") == "" && r.Header.Get("Authorization") == ""
		incoming.Unlock()
		panel.ServeHTTP(w, r)
	}))
	t.Cleanup(collector.Close)
	sites, err := store.Sites()
	if err != nil || len(sites) != 2 {
		t.Fatal(sites, err)
	}
	wafOff := false
	keys, originalFiles, originalContent := map[string]string{}, map[string][]byte{}, map[string][]byte{}
	for i := range sites {
		sites[i].Settings = core.DefaultSiteSettings(core.SiteSettings{WAFEnabled: &wafOff})
		sites[i].Status = "running"
		if sites[i].Slug == "native-php" {
			sites[i].PHPVersionID = "php-8.4.25"
			sites[i].Settings.Rewrite = "thinkphp"
		}
		public := filepath.Join("/srv/panel/sites", sites[i].ID, "public")
		if err := os.MkdirAll(public, 0755); err != nil {
			t.Fatal(err)
		}
		html := []byte(`<head><script>const untouched="</head>";</script><title>中文😀</title></head><body>original ` + sites[i].Slug + `</body>`)
		name, source := "index.html", html
		if sites[i].PHPVersionID != "" {
			name = "index.php"
			source = []byte(`<?php header('Content-Type: text/html; charset=utf-8'); header("Content-Security-Policy: script-src 'self'"); header('ETag: "php-original"'); header('Last-Modified: Thu, 08 Oct 2026 01:00:00 GMT'); echo ` + strconvQuotePHP(string(html)) + `;`)
		}
		path := filepath.Join(public, name)
		if err := os.WriteFile(path, source, 0644); err != nil {
			t.Fatal(err)
		}
		originalContent[path] = source
		text, err := renderSiteConfig(sites[i], public)
		if err != nil {
			t.Fatal(err)
		}
		conf := filepath.Join("/etc/panel/sites-enabled", sites[i].ID+".conf")
		originalFiles[conf] = []byte(text)
		if err := os.WriteFile(conf, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
		keys[sites[i].ID] = core.ID()
		if _, err := store.DB.Exec(`INSERT INTO analytics_config VALUES(?,?,0,1,30,1)`, sites[i].ID, keys[sites[i].ID]); err != nil {
			t.Fatal(err)
		}
	}
	writeAppliedMetadata := func(site core.Site, enabled bool) {
		t.Helper()
		data, _ := json.Marshal(site.Settings)
		if _, err := store.DB.Exec(`UPDATE sites SET settings_json=?,status='running',php_version_id=? WHERE id=?`, string(data), site.PHPVersionID, site.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB.Exec(`UPDATE analytics_config SET enabled=? WHERE site_id=?`, enabled, site.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, site := range sites {
		writeAppliedMetadata(site, false)
		if site.PHPVersionID == "" {
			continue
		}
		fpm := "/opt/panel/runtimes/php/8.4.25/sbin/php-fpm"
		if _, err := analyticsHTMLFileSHA(ctx, fpm, 64<<20); err != nil {
			t.Fatal("real PHP-FPM program identity", err)
		}
		socket := poolSocket(site)
		if err := os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(base, "private-fpm.conf")
		body := fmt.Sprintf("[global]\ndaemonize=no\nerror_log=%s\n[private]\nuser=panel-build\ngroup=panel-build\nlisten=%s\nlisten.mode=0660\nlisten.owner=panel-build\nlisten.group=panel-build\npm=static\npm.max_children=1\ncatch_workers_output=yes\n", filepath.Join(base, "private-fpm.log"), socket)
		if err := os.WriteFile(config, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		startAnalyticsHTMLPrivateProcess(t, fpm, "-n", "--nodaemonize", "-y", config)
		for attempt := 0; attempt < 100; attempt++ {
			if _, err := os.Stat(socket); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := os.Stat(socket); err != nil {
			t.Fatal("private real PHP-FPM socket absent; log retained", err)
		}
	}
	main := "user panel-build;\ndaemon off;\nmaster_process on;\npid /run/panel-nginx/nginx.pid;\nerror_log stderr notice;\nevents { worker_connections 32; }\nhttp {\n  include /etc/nginx/mime.types;\n  access_log off;\n  log_format panel_site '$remote_addr $status';\n"
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		main += fmt.Sprintf("  %s_temp_path /run/panel-nginx/%s-temp;\n", kind, kind)
	}
	main += "  server { listen 127.0.0.1:19101 default_server; server_name _; return 404; }\n  include /etc/panel/sites-enabled/*.conf;\n}\n" + strings.Repeat("# preserved administrator comment\n", 1200)
	if err := os.WriteFile("/etc/nginx/nginx.conf", []byte(main), 0640); err != nil {
		t.Fatal(err)
	}
	master := startAnalyticsHTMLPrivateProcess(t, nginx, "-e", "stderr", "-c", "/etc/nginx/nginx.conf")
	reloads, rejectNext, suppressNext := 0, false, false
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		if name == nginx {
			return RunCommand(ctx, name, args...)
		}
		if name != "/usr/bin/systemctl" || len(args) != 2 || args[1] != "nginx" {
			return "", fmt.Errorf("private runner refuses all original service commands: %s %v", name, args)
		}
		switch args[0] {
		case "is-active":
			if err := syscall.Kill(master.Process.Pid, 0); err != nil {
				return "inactive", err
			}
			return "active", nil
		case "reload":
			reloads++
			children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", master.Process.Pid, master.Process.Pid))
			if err != nil {
				return "", err
			}
			t.Log("private reload observed master/children", master.Process.Pid, strings.TrimSpace(string(children)))
			if rejectNext {
				rejectNext = false
				return "", errors.New("private QA rejects reload before any signal")
			}
			if suppressNext {
				suppressNext = false
				return "", nil // A command success is not a real worker acknowledgment.
			}
			return "", syscall.Kill(master.Process.Pid, syscall.SIGHUP)
		}
		return "", errors.New("private runner refuses unreviewed service operation")
	}
	s := New(Config{SitesDir: "/srv/panel/sites", ConfDir: "/etc/panel/sites-enabled", StateDir: "/var/lib/panel-executor", NginxBin: nginx, Run: runner})
	if err := moduleWrite(filepath.Join(s.moduleDir("website-analytics"), "installed.json"), map[string]any{"id": "website-analytics", "version": "2.3.0", "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	visit := func(site core.Site, path, method, data string, headers map[string]string) ([]byte, http.Header, int) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:19101"+path, strings.NewReader(data))
		request.Host = site.Domain
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("actual private site request", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return body, response.Header, response.StatusCode
	}
	waitSite := func(site core.Site, injected bool) {
		t.Helper()
		consecutive := 0
		var lastStatus int
		var lastFingerprint string
		for attempt := 0; attempt < 80; attempt++ {
			request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/", nil)
			request.Host = site.Domain
			response, err := client.Do(request)
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				lastStatus, lastFingerprint = response.StatusCode, response.Header.Get("X-Panel-Config")
				if response.StatusCode == 200 && lastFingerprint == core.Hash(siteHealthBody(site)) && bytes.Contains(body, []byte("/__yunzhan/analytics/auto.js?site=")) == injected {
					consecutive++
					if consecutive == 3 {
						return
					}
				} else {
					consecutive = 0
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("actual private worker did not reach expected site representation and configuration fingerprint", site.Domain, injected, lastStatus, lastFingerprint, core.Hash(siteHealthBody(site)))
	}
	for _, site := range sites {
		waitSite(site, false)
	}
	if err := s.activateAnalyticsHTML(ctx, id); err != nil {
		t.Fatal("actual global module activation", err)
	}
	if err := s.requireAnalyticsHTMLReady(ctx); err != nil {
		t.Fatal("actual Unix-socket worker identity", err)
	}
	for path, content := range originalFiles {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, content) {
			t.Fatal("global engine activated a website without opt-in", path)
		}
	}
	beforeReplay := reloads
	if err := s.activateAnalyticsHTML(ctx, id); err != nil || reloads != beforeReplay {
		t.Fatal("lost-reply replays caused a reload/repair", err, reloads, beforeReplay)
	}
	for i := range sites {
		sites[i].Settings.AnalyticsInjectHTML = true
		sites[i].Settings.AnalyticsEndpoint = strings.TrimPrefix(collector.URL, "http://")
		text, err := renderSiteConfig(sites[i], filepath.Join("/srv/panel/sites", sites[i].ID, "public"))
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(filepath.Join("/etc/panel/sites-enabled", sites[i].ID+".conf"), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runner(ctx, nginx, "-t"); err != nil {
		t.Fatal("real generated static/PHP/ThinkPHP filters syntax", err)
	}
	if _, err := runner(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		waitSite(site, true)
		writeAppliedMetadata(site, true)
		body, header, status := visit(site, "/", "GET", "", nil)
		if header.Get("X-Panel-Config") != core.Hash(siteHealthBody(site)) {
			t.Fatal("homepage unexpectedly returned an old configuration after worker handoff", site.Domain, status, header.Get("X-Panel-Config"), core.Hash(siteHealthBody(site)))
		}
		insert := `<script defer src="/__yunzhan/analytics/auto.js?site=` + site.ID + `"></script>`
		if status != 200 || bytes.Count(body, []byte(insert)) != 1 || !bytes.Contains(body, []byte(`const untouched="</head>";`)) || header.Get("ETag") != "" || header.Get("Last-Modified") != "" {
			t.Fatal("actual static/PHP page corruption, duplicate injection or stale validators", site.Domain, status, header)
		}
		if site.PHPVersionID != "" {
			if header.Get("Content-Security-Policy") != "script-src 'self'" {
				t.Fatal("PHP CSP was changed")
			}
			compat, _, code := visit(site, "/api.php/private-route", "GET", "", nil)
			if code != 200 || !bytes.Equal(compat, body) {
				t.Fatal("actual ThinkPHP route lacks context-safe injection", code)
			}
		}
		script, scriptHeader, code := visit(site, "/__yunzhan/analytics/auto.js?site="+site.ID, "GET", "", map[string]string{"Cookie": "panel_session=must-not-forward", "Authorization": "Bearer must-not-forward"})
		if code != 200 || !bytes.Contains(script, []byte(keys[site.ID])) || scriptHeader.Get("Cache-Control") != "no-store" || len(scriptHeader.Values("Set-Cookie")) != 0 || scriptHeader.Get("X-Panel-Config") != core.Hash(siteHealthBody(site)) {
			t.Fatal("actual first-party collector script", site.Domain, code, scriptHeader, "expected configuration fingerprint", core.Hash(siteHealthBody(site)), "script bytes", len(script))
		}
		if _, _, code := visit(site, "/__yunzhan/analytics/api/ready", "GET", "", nil); code != 404 {
			t.Fatal("analytics proxy exposed panel management", code)
		}
	}
	site := sites[0]
	event := core.AnalyticsEvent{ID: core.ID(), PageID: core.ID(), Visitor: core.ID(), Session: core.ID(), Kind: "pageview", Path: "/actual-private-request"}
	data, _ := json.Marshal(event)
	path := "/__yunzhan/analytics/event?site=" + site.ID + "&key=" + keys[site.ID]
	for attempt := 0; attempt < 2; attempt++ {
		if _, _, code := visit(site, path, "POST", string(data), map[string]string{"Origin": "http://" + site.Domain, "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 Chrome/123.0", "Cookie": "panel_session=must-not-forward", "Authorization": "Bearer must-not-forward"}); code != 204 {
			t.Fatal("actual event/retry collector rejected", code)
		}
	}
	if _, _, code := visit(site, path, "POST", string(data), map[string]string{"Origin": "https://foreign.example", "Content-Type": "application/json"}); code != 403 {
		t.Fatal("foreign-origin event accepted", code)
	}
	var count int
	if err := store.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE site_id=?`, site.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("real collection duplicated, failed, or forged event retained", count, err)
	}
	incoming.Lock()
	clean := collectorHeadersClean
	incoming.Unlock()
	if !clean {
		t.Fatal("real proxy forwarded management credentials")
	}
	for i := range sites {
		sites[i].Settings.AnalyticsInjectHTML = false
		sites[i].Settings.AnalyticsEndpoint = ""
		text, err := renderSiteConfig(sites[i], filepath.Join("/srv/panel/sites", sites[i].ID, "public"))
		conf := filepath.Join("/etc/panel/sites-enabled", sites[i].ID+".conf")
		if err != nil || !bytes.Equal([]byte(text), originalFiles[conf]) {
			t.Fatal("disable failed to restore exact generated site configuration", err)
		}
		if err := atomicWrite(conf, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runner(ctx, nginx, "-t"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		waitSite(site, false)
		writeAppliedMetadata(site, false)
		body, headers, code := visit(site, "/__yunzhan/analytics/auto.js?site="+site.ID, "GET", "", nil)
		// Removing the owned proxy returns routing to the site's original
		// configuration. A ThinkPHP front controller may legitimately return
		// HTML 200 here; it must never remain a live collector or injected page.
		if (code != 404 && !(site.PHPVersionID != "" && code == 200)) || bytes.Contains(body, []byte(keys[site.ID])) || bytes.Contains(body, []byte("/__yunzhan/analytics/auto.js?site=")) || strings.Contains(headers.Get("Content-Type"), "javascript") || headers.Get("X-Panel-Config") != core.Hash(siteHealthBody(site)) {
			t.Fatal("disabled collector remained live or changed original routing", code, headers)
		}
	}
	for path, original := range originalContent {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, original) {
			t.Fatal("a static/PHP template was modified", path)
		}
	}
	if err := store.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE site_id=?`, site.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("stopping collector deleted history", count, err)
	}
	paths := s.analyticsHTMLTransactionService().analyticsHTMLConfigurationPaths()
	triplet := make([][]byte, len(paths))
	for i, path := range paths {
		triplet[i], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, fault := range []string{"reload-error", "false-command-success"} {
		rejectNext, suppressNext = fault == "reload-error", fault == "false-command-success"
		if err := s.activateAnalyticsHTML(ctx, nextID); err == nil {
			t.Fatal("failed actual worker transition was reported as success", fault)
		}
		for i, path := range paths {
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, triplet[i]) {
				t.Fatal("actual recovery did not preserve full original triplet", fault, path)
			}
		}
		if err := s.probeAnalyticsHTMLLoaded(ctx, first.analyticsHTMLEngineIdentity); err != nil {
			t.Fatal("rollback did not restore actual previous worker fingerprint", fault, err)
		}
		if _, err := os.Lstat(s.analyticsHTMLTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("verified native recovery did not archive pending journal", err)
		}
	}
	for _, candidate := range sites {
		if candidate.PHPVersionID == "" {
			analyticsHTMLNativeAuthenticatedSiteAPI(t, ctx, base, s, panel, store, candidate, strings.TrimPrefix(collector.URL, "http://"))
		}
	}
	t.Log("PASS actual private canonical activation/reload/Unix worker acknowledgment; static HTML + PHP-FPM + ThinkPHP + real first-party collector/replay/privacy/disable; both reload failures restore exact triplet and actual old worker; no original services or template files changed; not a signed API/build-unit/power-loss acceptance")
}

func strconvQuotePHP(value string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "'", "\\'") + "'"
}

func startAnalyticsHTMLPrivateProcess(t *testing.T, executable string, args ...string) *exec.Cmd {
	t.Helper()
	log, err := os.OpenFile(filepath.Join(os.TempDir(), "analytics-private-process-"+core.ID()+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		log.Close()
	})
	return cmd
}
