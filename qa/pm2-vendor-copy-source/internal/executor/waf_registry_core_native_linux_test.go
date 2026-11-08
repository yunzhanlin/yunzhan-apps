//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

// Only the manifest transport is offline. It supplies the exact existing
// official signed package bytes, not a test key/catalog or an installed
// manifest. Core validates its real default key and runs the actual executor.
// This deliberately does NOT claim a live GitHub fetch or browser acceptance.
type wafNativeManifestTransport struct {
	body  []byte
	mu    sync.Mutex
	calls int
}

func (transport *wafNativeManifestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "GET" || r.URL.String() != appcatalog.DefaultBaseURL+"/dist/apps/nginx-waf/2.5.1/manifest.json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return nil, errors.New("private fixture denies every other repository read; no fabricated Git reference")
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	transport.mu.Lock()
	transport.calls++
	transport.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(transport.body)), ContentLength: int64(len(transport.body)), Request: r}, nil
}

func TestWAFNativeRegistryAuthenticatedCoreLifecycle(t *testing.T) {
	if os.Getenv("PANEL_QA_WAF_REGISTRY_CORE_NATIVE") != "1" {
		t.Skip("requires exact private canonical namespace, real producer and official signed application bytes")
	}
	id := os.Getenv("PANEL_WAF_ENGINE_QA_JOB")
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || strings.TrimSpace(string(host)) != map[string]string{"arm64": "lima-panel-ids24hj-clean-ubuntu24", "amd64": "lima-panel-analytics23t-unit-debian13"}[runtime.GOARCH] {
		t.Fatal("not an authorized existing own fixture")
	}
	if err := verifyNginxNativeWorkerCapabilities(); err != nil {
		t.Fatal(err)
	}
	var marker struct {
		Format        int    `json:"format"`
		Mount         string `json:"init_mount_namespace"`
		Network       string `json:"init_network_namespace"`
		Job           string `json:"job_id"`
		BrowserOrigin string `json:"browser_origin"`
	}
	if err := readAnalyticsHTMLPrivateJSON("/etc/panel/.native-waf-http-fixture.json", 2048, &marker); err != nil || marker.Format != 1 || marker.Job != id {
		t.Fatal("own namespace witness", err)
	}
	panelOrigin, originErr := wafNativeBrowserOrigin(marker.BrowserOrigin, os.Getenv("PANEL_QA_WAF_CORE_BROWSER_WIRE") == "1")
	if originErr != nil {
		t.Fatal(originErr)
	}
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) != nil || fs.Flags&1 == 0 {
		t.Fatal("original root must be read-only")
	}
	for name, original := range map[string]string{"mnt": marker.Mount, "net": marker.Network} {
		current, e := os.Readlink("/proc/self/ns/" + name)
		if e != nil || !regexp.MustCompile("^"+name+`:\[[1-9][0-9]{0,19}\]$`).MatchString(original) || current == original {
			t.Fatal("refuse original namespace")
		}
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("actual source producer", err)
	}
	record, err := readWAFBuildRecord(id)
	if err != nil || record.NginxBinary != "/usr/sbin/nginx" {
		t.Fatal("expected the genuine selected system binary", err)
	}
	// Keep the fixture finite and within its existing 280s test / 300s unit
	// envelope; do not give an individual executor call more than its actual
	// production 90s client limit. Full rule loading and a refused false-ack
	// now include distinct bounded listener handoff and recovery phases.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Second)
	defer cancel()
	const fixture = "/run/panel-waf-produced-http24apg"
	if err := ownedRuntimePath(fixture, true); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(fixture, "core-registry-")
	if err != nil || os.Chmod(base, 0755) != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/panel/sites-enabled", "/etc/panel/security-apps", "/run/panel-nginx", filepath.Join(base, "data"), filepath.Join(base, "web")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// The supervisor intentionally keeps umask 0077. Public serving paths,
	// unlike the database/locks/receipts, need explicit traversal for UID 33.
	if err := os.Chmod("/run/panel-nginx", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile("/var/lib/panel-executor/runtime-lifecycle.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("fresh private installer prerequisite", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := core.OpenStore(filepath.Join(base, "data/panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 8192)); err != nil {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, "native-body-upstream\n")
	}))
	t.Cleanup(upstream.Close)
	sites := []core.Site{}
	baselineSites := map[string][]byte{}
	for _, slug := range []string{"waf-native-selected", "waf-native-optout"} {
		if _, err := store.CreateSiteAtDomain("Private WAF registry", slug, slug+".example.test", core.ID(), "private initial website fixture"); err != nil {
			t.Fatal(err)
		}
	}
	sites, err = store.Sites()
	if err != nil || len(sites) != 2 {
		t.Fatal(err)
	}
	var selected, optedOut core.Site
	for i := range sites {
		on := sites[i].Slug == "waf-native-selected"
		sites[i].Settings = core.DefaultSiteSettings(core.SiteSettings{WAFEnabled: &on})
		sites[i].Status = "running"
		public := filepath.Join("/srv/panel/sites", sites[i].ID, "public")
		if err := os.MkdirAll(public, 0755); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{filepath.Dir(public), public} {
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := atomicWrite(filepath.Join(public, "index.html"), []byte("native-original-home\n"), 0644); err != nil {
			t.Fatal(err)
		}
		text, err := renderSiteConfig(sites[i], public)
		if err != nil {
			t.Fatal(err)
		}
		last := strings.LastIndex(text, "}\n")
		if last < 0 {
			t.Fatal("managed site rendering")
		}
		text = text[:last] + "  location = /body { proxy_pass " + upstream.URL + "; }\n" + text[last:]
		path := filepath.Join("/etc/panel/sites-enabled", sites[i].ID+".conf")
		if err := atomicWrite(path, []byte(text), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 33); err != nil {
			t.Fatal(err)
		}
		baselineSites[sites[i].ID] = []byte(text)
		settings, _ := json.Marshal(sites[i].Settings)
		if _, err := store.DB.Exec(`UPDATE sites SET settings_json=?,status='running' WHERE id=?`, string(settings), sites[i].ID); err != nil {
			t.Fatal(err)
		}
		if on {
			selected = sites[i]
		} else {
			optedOut = sites[i]
		}
	}
	// Initial websites are explicitly fixture setup, never app install proof.
	if _, err := store.DB.Exec(`UPDATE jobs SET state='succeeded' WHERE kind='create_site' AND state='queued'`); err != nil {
		t.Fatal(err)
	}
	main := "user www-data;\ndaemon off;\nmaster_process on;\nworker_processes 2;\npid /run/panel-nginx/nginx.pid;\nerror_log /run/panel-nginx/error.log notice;\nevents { worker_connections 64; }\nhttp {\n  include /etc/nginx/mime.types;\n  access_log off;\n  log_format panel_site '$remote_addr $status';\n"
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		main += fmt.Sprintf("  %s_temp_path /run/panel-nginx/%s-temp;\n", kind, kind)
	}
	main += "  server { listen 127.0.0.1:19101 default_server; server_name _; return 404; }\n  include /etc/panel/sites-enabled/*.conf;\n}\n"
	if err := atomicWrite("/etc/nginx/nginx.conf", []byte(main), 0640); err != nil {
		t.Fatal(err)
	}
	master := startAnalyticsHTMLPrivateProcess(t, "/usr/bin/setpriv", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--", record.NginxBinary, "-e", "stderr", "-c", "/etc/nginx/nginx.conf")
	var runnerMu sync.Mutex
	reloads := 0
	fault := ""
	runner := func(ctx context.Context, name string, args ...string) (string, error) {
		if name == record.NginxBinary {
			return RunCommand(ctx, name, args...)
		}
		if name != "/usr/bin/systemctl" {
			return "", errors.New("fixture denies all other host commands")
		}
		if reflect.DeepEqual(args, []string{"show", "nginx", "--property=ActiveState,MainPID"}) {
			if err := syscall.Kill(master.Process.Pid, 0); err != nil {
				return "", err
			}
			return fmt.Sprintf("ActiveState=active\nMainPID=%d\n", master.Process.Pid), nil
		}
		if reflect.DeepEqual(args, []string{"is-active", "nginx"}) {
			if err := syscall.Kill(master.Process.Pid, 0); err != nil {
				return "inactive", err
			}
			return "active", nil
		}
		if !reflect.DeepEqual(args, []string{"reload", "nginx"}) {
			return "", errors.New("fixture denies every unreviewed service operation")
		}
		runnerMu.Lock()
		reloads++
		next := fault
		fault = ""
		runnerMu.Unlock()
		if next == "reject" {
			return "", errors.New("private fault: refused before signaling the owned master")
		}
		if next == "false-ack" {
			return "", nil
		}
		return "", syscall.Kill(master.Process.Pid, syscall.SIGHUP)
	}
	s := New(Config{SitesDir: "/srv/panel/sites", ConfDir: "/etc/panel/sites-enabled", StateDir: "/var/lib/panel-executor", NginxBin: record.NginxBinary, Run: runner})
	if _, err := s.readSoftwareManifest("nginx-waf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("application must not be preinstalled", err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	visit := func(site core.Site, method, path, data string) int {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:19101"+path, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = site.Domain
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal("real private site request", err)
		}
		defer res.Body.Close()
		_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 65536))
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	ready := false
	for i := 0; i < 100; i++ {
		r, err := client.Get("http://127.0.0.1:19101/")
		if err == nil {
			r.Body.Close()
			ready = r.StatusCode == 404
			if ready {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("own actual master failed to serve")
	}
	verifyWAFProducedHTTPWorkers(t, master.Process.Pid, record.NginxBinary, 33)
	for _, site := range sites {
		if status := visit(site, "GET", "/", ""); status != 200 {
			t.Fatal("initial actual managed website", site.Slug, status)
		}
	}
	panel, err := core.NewServer(store, core.Config{DataDir: filepath.Join(base, "data"), WebDir: filepath.Join(base, "web"), Origin: panelOrigin, Listen: "127.0.0.1:19100", Socket: filepath.Join(base, "executor.sock")})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("/etc/panel/.native-waf-catalog.bundle.json")
	if err != nil || core.Hash(string(bundle)) != "c7e4925bb34c7f626e3eefa023be3d939aaae2f865069c6b85ffc6de804e965c" {
		t.Fatal("official frozen signed catalog bytes", err)
	}
	manifest, err := os.ReadFile("/etc/panel/.native-waf-manifest.json")
	const manifestSHA = "eed95299d56d674277e6d489318ff5d43b4fa6e215cd3e65f7be3819fd047403"
	if err != nil || core.Hash(string(manifest)) != manifestSHA {
		t.Fatal("official frozen manifest bytes", err)
	}
	cache := filepath.Join(base, "data/app-registry/catalog")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(cache, "catalog-v1.bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	transport := &wafNativeManifestTransport{body: manifest}
	panel.AppCatalog = appcatalog.Default()
	panel.AppCatalog.HTTP = &http.Client{Transport: transport, Timeout: 2 * time.Second}
	catalog, info, err := panel.AppCatalog.LoadCatalog(ctx, cache, time.Minute)
	item, found := appcatalog.Find(catalog, "nginx-waf")
	if err != nil || info.Source != "verified-cache" || !found || item.SHA256 != manifestSHA || item.Version != core.WAFVersion || len(catalog.Apps) != 50 {
		t.Fatal("actual default-public-key catalog verification", err)
	}
	var endpointMu sync.Mutex
	mutations, preFinish, denied, archiveMutations := 0, 0, 0, 0
	loseArchiveReply := false
	handler := s.Handler()
	listener, err := net.Listen("unix", filepath.Join(base, "executor.sock"))
	if err != nil || os.Chmod(filepath.Join(base, "executor.sock"), 0600) != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupRead := r.Method == "GET" && (r.URL.Path == "/v1/software/nginx-waf/config-backup-slots" || r.URL.Path == "/v1/software/nginx-waf/config-backup-archive")
		for _, prefix := range []string{"/v1/software/nginx-waf/config-backups/", "/v1/software/nginx-waf/config-backup-archive/"} {
			if strings.HasPrefix(r.URL.Path, prefix) && core.ValidID(strings.TrimPrefix(r.URL.Path, prefix)) && r.Method == "GET" {
				backupRead = true
			}
		}
		archiveWrite := r.Method == "POST" && r.URL.Path == "/v1/software/nginx-waf/archive-config-backup"
		browserRead := marker.BrowserOrigin != "" && r.Method == "GET" && (r.URL.Path == "/v1/software/nginx-waf/engines" || r.URL.Path == "/v1/software/nginx-waf/body-log/archives" || r.URL.Path == "/v1/software/nginx-waf/body-log/rotation")
		allowed := backupRead || archiveWrite || browserRead || r.Method == "GET" && (r.URL.Path == "/v1/software" || r.URL.Path == "/v1/software/nginx-waf/config" || r.URL.Path == "/v1/software/nginx-waf/body-report" || r.URL.Path == "/v1/software/nginx-waf/config-backups") || r.Method == "POST" && (r.URL.Path == "/v1/software/nginx-waf/install" || r.URL.Path == "/v1/software/nginx-waf/configure" || r.URL.Path == "/v1/software/nginx-waf/preview")
		if !allowed {
			endpointMu.Lock()
			denied++
			endpointMu.Unlock()
			respond(w, 503, map[string]string{"error": "private fixture excludes all other capabilities; unknown is not healthy"})
			return
		}
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, r)
		if archiveWrite {
			endpointMu.Lock()
			archiveMutations++
			lost := loseArchiveReply
			loseArchiveReply = false
			endpointMu.Unlock()
			if lost && result.Code == 200 {
				respond(w, 503, map[string]string{"error": "own fixture loses an already verified archive response; outcome must remain unknown"})
				return
			}
		}
		if r.Method == "POST" && r.URL.Path != "/v1/software/nginx-waf/preview" && !archiveWrite {
			endpointMu.Lock()
			mutations++
			endpointMu.Unlock()
			if r.URL.Path == "/v1/software/nginx-waf/install" && result.Code == 200 {
				var receipts, running int
				e1 := store.DB.QueryRow(`SELECT count(*) FROM app_registry_receipts`).Scan(&receipts)
				e2 := store.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id='nginx-waf' AND kind='software_install' AND state='running'`).Scan(&running)
				if e1 != nil || e2 != nil || receipts != 0 || running != 1 {
					respond(w, 500, map[string]string{"error": "receipt or job changed before actual Core Finish"})
					return
				}
				endpointMu.Lock()
				preFinish++
				endpointMu.Unlock()
			}
		}
		for k, v := range result.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(result.Code)
		_, _ = w.Write(result.Body.Bytes())
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	panel.Executor = core.NewExecutorClient(filepath.Join(base, "executor.sock"))
	t.Cleanup(panel.Executor.Client.CloseIdleConnections)
	request := func(method, path string, body []byte, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, panel.Config.Origin+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", panel.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	token, err := os.ReadFile(filepath.Join(base, "data/bootstrap-token"))
	if err != nil || store.UserCount() != 0 {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"username": "nativeadmin", "password": "private-native-core-password-long", "token": strings.TrimSpace(string(token))})
	if w := request("POST", "/api/bootstrap", data, "", "", nil); w.Code != 201 {
		t.Fatal("actual bootstrap", w.Code)
	}
	login := request("POST", "/api/login", []byte(`{"username":"nativeadmin","password":"private-native-core-password-long"}`), "", "", nil)
	var auth struct {
		CSRF string `json:"csrf"`
	}
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(login.Result().Cookies()) != 1 {
		t.Fatal("actual login", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	var ownUser string
	if err := store.DB.QueryRow(`SELECT id FROM users WHERE username='nativeadmin'`).Scan(&ownUser); err != nil || !core.ValidID(ownUser) {
		t.Fatal("private fixture administrator identity", err)
	}
	// The fixture administrator can manage WAF software, not global audit jobs.
	// These grants affect only this fresh private database, not the real host.
	if _, err := store.DB.Exec(`INSERT INTO app_user_menus(user_id,menu_ids,revision) VALUES(?,'["runtimes","security"]',1) ON CONFLICT(user_id) DO UPDATE SET menu_ids=excluded.menu_ids,revision=app_user_menus.revision+1`, ownUser); err != nil {
		t.Fatal(err)
	}
	if w := request("GET", "/api/sites", nil, auth.CSRF, "", cookie); w.Code != 403 {
		t.Fatal("private WAF administrator gained general website access", w.Code)
	}
	if w := request("GET", "/api/software/nginx-waf/sites", nil, "", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated WAF website selector", w.Code)
	}
	for _, engine := range []string{"nginx-waf", "apache-waf"} {
		w := request("GET", "/api/software/"+engine+"/sites", nil, auth.CSRF, "", cookie)
		var page struct {
			Sites []struct {
				ID       string `json:"id"`
				Settings struct {
					WAFEnabled bool   `json:"waf_enabled"`
					WebServer  string `json:"web_server"`
				} `json:"settings"`
			} `json:"sites"`
			NextCursor string `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.NextCursor != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("actual minimal WAF website selector", engine, w.Code)
		}
		if engine == "nginx-waf" {
			if len(page.Sites) != 2 {
				t.Fatal("actual Nginx site inventory", len(page.Sites))
			}
			for _, site := range page.Sites {
				if site.ID != selected.ID && site.ID != optedOut.ID || site.Settings.WebServer != "nginx" || site.Settings.WAFEnabled != (site.ID == selected.ID) {
					t.Fatal("actual opt-out/default WAF selector contract", site)
				}
			}
		} else if len(page.Sites) != 0 {
			t.Fatal("Apache selector returned actual Nginx websites")
		}
		for _, hidden := range []string{"document_root", "proxy_url", "php_version_id", "runtime_instance_id", "settings_revision", "domains", "tls", "slug"} {
			if strings.Contains(w.Body.String(), `"`+hidden+`"`) {
				t.Fatal("actual WAF selector leaked website data", hidden)
			}
		}
	}
	if w := request("GET", "/api/software/nginx-waf/config", nil, "", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated global configuration", w.Code)
	}
	read := func() core.WAFConfig {
		t.Helper()
		w := request("GET", "/api/software/nginx-waf/config", nil, auth.CSRF, "", cookie)
		var out struct {
			Settings core.WAFConfig         `json:"settings"`
			Status   core.SoftwareAppStatus `json:"status"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("actual configuration API", w.Code, w.Body.String())
		}
		return out.Settings
	}
	registry := func() core.AppRegistryStatus {
		t.Helper()
		w := request("GET", "/api/app-registry", nil, auth.CSRF, "", cookie)
		var out core.AppRegistryPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Source.Source != "verified-cache" {
			t.Fatal("actual verified-cache registry API", w.Code, w.Body.String())
		}
		for _, row := range out.Status {
			if row.ID == "nginx-waf" {
				return row
			}
		}
		t.Fatal("missing genuine catalog app")
		return core.AppRegistryStatus{}
	}
	if row := registry(); !row.StateKnown || row.Installed {
		t.Fatal("initial real software status", row)
	}
	initial := core.DefaultWAFConfig()
	initial.Policy.Mode = "off"
	initial.Policy.CCEnabled = false
	installBody, _ := json.Marshal(map[string]any{"expected_version": item.Version, "expected_sha256": item.SHA256, "settings": core.WAFSettings(initial)})
	installPath := "/api/app-registry/nginx-waf/install"
	if w := request("POST", installPath, installBody, "", "native-official-install", cookie); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	queue := func(path string, body []byte, key string) string {
		t.Helper()
		w := request("POST", path, body, auth.CSRF, key, cookie)
		var out map[string]any
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("actual queue", path, w.Code, w.Body.String())
		}
		id, ok := out["job_id"].(string)
		if !ok || !core.ValidID(id) {
			t.Fatal("missing real task identity")
		}
		return id
	}
	installJob := queue(installPath, installBody, "native-official-install")
	type originalRequestSummary struct {
		ID            string `json:"id"`
		TargetID      string `json:"target_id"`
		Kind          string `json:"kind"`
		State         string `json:"state"`
		CreatedAt     string `json:"created_at"`
		PayloadSHA    string `json:"request_sha256"`
		SignedInstall bool   `json:"signed_install_binding"`
	}
	readOriginalRequest := func(job string, actorCookie *http.Cookie) originalRequestSummary {
		t.Helper()
		w := request("GET", "/api/software/nginx-waf/requests/"+job, nil, "", "", actorCookie)
		var out struct {
			Request  originalRequestSummary `json:"request"`
			Error    string                 `json:"error"`
			Settings map[string]any         `json:"settings"`
			ReadOnly bool                   `json:"read_only"`
		}
		var shape map[string]json.RawMessage
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || json.Unmarshal(w.Body.Bytes(), &shape) != nil || len(shape) != 4 || !out.ReadOnly || out.Request.ID != job || out.Request.TargetID != "nginx-waf" || out.Request.CreatedAt == "" {
			t.Fatal("actual original task request read", w.Code, w.Body.String())
		}
		var payload, kind string
		if err := store.DB.QueryRow(`SELECT payload,kind FROM runtime_jobs WHERE id=?`, job).Scan(&payload, &kind); err != nil || kind != out.Request.Kind || core.Hash(payload) != out.Request.PayloadSHA {
			t.Fatal("actual original task payload binding", err)
		}
		var stored struct {
			Settings map[string]any `json:"settings"`
		}
		if json.Unmarshal([]byte(payload), &stored) != nil || !reflect.DeepEqual(stored.Settings, out.Settings) {
			t.Fatal("original settings replaced instead of restored")
		}
		if _, err := core.DecodeWAFConfig(out.Settings); err != nil {
			t.Fatal("actual complete original config", err)
		}
		for _, secret := range []string{"actor_id", "username", "idempotency_key", "steps"} {
			if strings.Contains(w.Body.String(), `"`+secret+`"`) {
				t.Fatal("original recovery expanded private fields", secret)
			}
		}
		return out.Request
	}
	readOriginalDirectory := func(want int, actorCookie *http.Cookie) []originalRequestSummary {
		t.Helper()
		w := request("GET", "/api/software/nginx-waf/requests", nil, "", "", actorCookie)
		var out struct {
			Entries  []originalRequestSummary `json:"entries"`
			Next     string                   `json:"next_cursor"`
			ReadOnly bool                     `json:"read_only"`
		}
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.ReadOnly || len(out.Entries) != want || out.Next != "" {
			t.Fatal("actual actor-bound original directory", w.Code, w.Body.String())
		}
		for i, row := range out.Entries {
			if !core.ValidID(row.ID) || row.TargetID != "nginx-waf" || i > 0 && row.ID <= out.Entries[i-1].ID || !reflect.DeepEqual(row, readOriginalRequest(row.ID, actorCookie)) {
				t.Fatal("actual bounded directory/detailed identity mismatch", row)
			}
		}
		return out.Entries
	}
	queuedOriginal := readOriginalRequest(installJob, cookie)
	if queuedOriginal.State != "queued" || queuedOriginal.Kind != "software_install" || !queuedOriginal.SignedInstall {
		t.Fatal("queued original request became actual installation proof", queuedOriginal)
	}
	readOriginalDirectory(1, cookie)
	if w := request("GET", "/api/software/nginx-waf/jobs/"+installJob, nil, "", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated original task read", w.Code)
	}
	if w := request("GET", "/api/jobs/"+installJob, nil, auth.CSRF, "", cookie); w.Code != 403 {
		t.Fatal("private WAF administrator gained unrelated global audit access", w.Code)
	}
	if w := request("GET", "/api/software/apache-waf/jobs/"+installJob, nil, auth.CSRF, "", cookie); w.Code != 404 {
		t.Fatal("wrong WAF accepted original task", w.Code)
	}
	if _, err := s.readSoftwareManifest("nginx-waf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("queue preinstalled app", err)
	}
	var receipts, pending int
	if err := store.DB.QueryRow(`SELECT count(*) FROM app_registry_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("queued receipt", err)
	}
	if err := store.DB.QueryRow(`SELECT count(*) FROM app_registry_pending WHERE job_id=?`, installJob).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("missing pending signed binding", err)
	}
	if queue(installPath, installBody, "native-official-install") != installJob {
		t.Fatal("queued lost reply changed task")
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { core.RunWorker(workerCtx, store, panel.Executor); close(done) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("own Core worker failed to stop")
		}
	}()
	authenticatedJobReads := 0
	wait := func(id string, wantSuccess bool) {
		t.Helper()
		for deadline := time.Now().Add(95 * time.Second); time.Now().Before(deadline) && ctx.Err() == nil; {
			w := request("GET", "/api/software/nginx-waf/jobs/"+id, nil, auth.CSRF, "", cookie)
			var job core.Job
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &job) != nil || job.ID != id || job.TargetID != "nginx-waf" || (job.Kind != "software_install" && job.Kind != "software_configure") || (id == installJob) != (job.Kind == "software_install") {
				t.Fatal("actual authenticated original task identity", w.Code)
			}
			authenticatedJobReads++
			state, detail := job.State, job.Error
			if state == "succeeded" {
				if !wantSuccess {
					t.Fatal("failed reload falsely succeeded")
				}
				return
			}
			if state == "failed" || state == "needs_attention" {
				if wantSuccess {
					t.Fatal("actual Core worker failed", state, detail)
				}
				if detail == "" {
					t.Fatal("missing failure evidence")
				}
				return
			}
			if state != "queued" && state != "running" {
				t.Fatal("actual original task state unknown", state)
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("actual Core runtime job did not finish")
	}
	wait(installJob, true)
	installed := read()
	if installed.Policy.Mode != "off" || installed.Policy.Revision != 1 || installed.Body != nil {
		t.Fatal("real installed policy")
	}
	row := registry()
	if !row.StateKnown || !row.Installed || !row.Healthy || !row.VersionKnown || row.InstalledVersion != item.Version || row.UpdateAvailable {
		t.Fatal("real successful install registry status", row)
	}
	var version, digest, target string
	if err := store.DB.QueryRow(`SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='nginx-waf' AND scope='nginx-waf'`).Scan(&version, &digest, &target); err != nil || version != item.Version || digest != item.SHA256 || target != item.Target {
		t.Fatal("real signed package receipt after actual Finish", err)
	}
	if queue(installPath, installBody, "native-official-install") != installJob {
		t.Fatal("finished lost reply changed task")
	}
	transport.mu.Lock()
	pulls := transport.calls
	transport.mu.Unlock()
	if pulls != 1 {
		t.Fatal("replayed install repulled manifest", pulls)
	}
	attack := "q=%27%20OR%201%3D1--&private=native-private-body-never-log"
	assertHTTP := func(want int) {
		t.Helper()
		if got := visit(selected, "POST", "/body", attack); got != want {
			t.Fatal("actual selected body policy", got, want)
		}
		if got := visit(optedOut, "POST", "/body", attack); got != 200 {
			t.Fatal("unselected site silently enabled", got)
		}
	}
	assertHTTP(200)
	configure := func(draft core.WAFConfig, key string, wantSuccess bool) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"settings": core.WAFSettings(draft)})
		job := queue("/api/software/nginx-waf/configure", body, key)
		wait(job, wantSuccess)
		if queue("/api/software/nginx-waf/configure", body, key) != job {
			t.Fatal("configuration lost reply changed task")
		}
		return job
	}
	active := installed
	active.Policy.Mode = "block"
	for name := range active.Policy.Groups {
		active.Policy.Groups[name] = false
	}
	policy := core.DefaultWAFBodyPolicy()
	policy.Mode = "block"
	active.Body = &core.WAFBodyConfig{EngineJobID: id, Sites: []core.WAFBodySitePolicy{{SiteID: selected.ID, Policy: policy}}}
	previewBody, _ := json.Marshal(map[string]any{"settings": core.WAFSettings(active)})
	if w := request("POST", "/api/software/nginx-waf/preview", previewBody, auth.CSRF, "", cookie); w.Code != 200 {
		t.Fatal("real source-verified preview", w.Code, w.Body.String())
	}
	if read().Policy.Revision != installed.Policy.Revision {
		t.Fatal("preview committed policy")
	}
	configure(active, "native-body-block", true)
	active = read()
	assertHTTP(403)
	verifyWAFProducedHTTPWorkers(t, master.Process.Pid, record.NginxBinary, 33)
	active.Policy.Mode = "observe"
	configure(active, "native-body-observe", true)
	active = read()
	assertHTTP(200)
	// Genuine reload faults traverse the real worker and transaction recovery.
	// No fabricated success/health or manually finished runtime task is used.
	for _, injected := range []string{"reject", "false-ack"} {
		paths := []string{s.Config.NginxConf, s.softwareManifestPath("nginx-waf"), filepath.Join(s.Config.ConfDir, selected.ID+".conf"), filepath.Join(s.Config.ConfDir, optedOut.ID+".conf")}
		h, v := wafFiles(s)
		paths = append(paths, h, v, s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf"), s.systemPath("/etc/panel/waf/body.d/"+selected.ID+".conf"))
		before := []fileBackup{}
		for _, path := range paths {
			b, err := backupFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before = append(before, b)
		}
		draft := read()
		draft.Policy.Mode = "block"
		runnerMu.Lock()
		fault = injected
		runnerMu.Unlock()
		configure(draft, "native-failure-"+injected, false)
		for i, path := range paths {
			actual, err := backupFile(path)
			if err != nil || !reflect.DeepEqual(actual, before[i]) {
				t.Fatal("native rollback changed original bytes/mode/UID/GID", path, err)
			}
		}
		if read().Policy.Revision != active.Policy.Revision {
			t.Fatal("failed transaction committed revision")
		}
		if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("verified rollback left a live pending transaction", err)
		}
		assertHTTP(200)
		if row := registry(); !row.Installed || !row.Healthy || row.InstalledVersion != item.Version {
			t.Fatal("configuration failure destroyed installed receipt", row)
		}
	}
	active = read()
	active.Policy.Mode = "off"
	offJob := configure(active, "native-body-off", true)
	disabled := read()
	assertHTTP(200)
	if disabled.Body == nil || disabled.Body.EngineJobID != id || disabled.Body.Sites[0].Policy.Mode != "block" {
		t.Fatal("global off deleted the independent policy/producer identity")
	}
	selectedText, err := os.ReadFile(filepath.Join(s.Config.ConfDir, selected.ID+".conf"))
	optoutText, e2 := os.ReadFile(filepath.Join(s.Config.ConfDir, optedOut.ID+".conf"))
	if err != nil || e2 != nil || bytes.Contains(selectedText, []byte("modsecurity on")) || !bytes.Equal(optoutText, baselineSites[optedOut.ID]) {
		t.Fatal("disable left body enabled or altered opted-out website", errors.Join(err, e2))
	}
	metadata, err := s.readWAFBodyEvents()
	if err != nil || !metadata.Available || len(metadata.Events) == 0 {
		t.Fatal("actual native body metadata missing", err)
	}
	for _, event := range metadata.Events {
		if event.SiteID != selected.ID {
			t.Fatal("unexpected body event scope", event.SiteID)
		}
	}
	actualLog, err := s.openWAFBodyLog(false, false)
	if err != nil {
		t.Fatal(err)
	}
	actualBytes, logReadErr := io.ReadAll(io.LimitReader(actualLog, (4<<20)+1))
	actualLog.Close()
	if logReadErr != nil || len(actualBytes) > 4<<20 || bytes.Contains(actualBytes, []byte("native-private-body-never-log")) {
		t.Fatal("native private request data escaped into the managed metadata log", logReadErr)
	}
	if w := request("GET", "/api/software/nginx-waf/body-report?site_id="+selected.ID+"&limit=100", nil, auth.CSRF, "", cookie); w.Code != 200 {
		t.Fatal("actual authenticated native report", w.Code, w.Body.String())
	}
	if w := request("GET", "/api/software/nginx-waf/body-report?limit=100&limit=100", nil, auth.CSRF, "", cookie); w.Code != 400 {
		t.Fatal("duplicate report filter accepted", w.Code)
	}
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("application lifecycle changed genuine source producer", err)
	}
	allOriginalRequests := readOriginalDirectory(6, cookie)
	originalInstallCount := 0
	for _, row := range allOriginalRequests {
		if row.Kind == "software_install" {
			originalInstallCount++
			if row.ID != installJob || !row.SignedInstall {
				t.Fatal("actual original signed install identity")
			}
		} else if row.Kind != "software_configure" || row.SignedInstall {
			t.Fatal("actual original configuration kind changed")
		}
	}
	if originalInstallCount != 1 {
		t.Fatal("original lifecycle binding coverage count", originalInstallCount)
	}
	backupsBefore := wafInventoryTree(t, s.Config.SecurityDir)
	w := request("GET", "/api/software/nginx-waf/config-backups", nil, auth.CSRF, "", cookie)
	inventory, inventoryError := core.DecodeWAFBackupInventory(w.Body.Bytes())
	if w.Code != 200 || inventoryError != nil || !inventory.Available || len(inventory.Entries) != 6 || inventory.Bytes <= 0 || !inventory.ReadOnly || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "/etc/") || strings.Contains(w.Body.String(), "native-private-body-never-log") || strings.Contains(w.Body.String(), `"source"`) {
		t.Fatal("actual complete original configuration inventory", w.Code, inventoryError)
	}
	for _, path := range []string{"/api/software/nginx-waf/config-backups?", "/api/software/nginx-waf/config-backups?path=/etc/shadow"} {
		if w := request("GET", path, nil, auth.CSRF, "", cookie); w.Code != 400 {
			t.Fatal("actual inventory query refused", w.Code)
		}
	}
	if w := request("GET", "/api/software/nginx-waf/config-backups", nil, "", "", nil); w.Code != 401 {
		t.Fatal("anonymous inventory read", w.Code)
	}
	if !reflect.DeepEqual(backupsBefore, wafInventoryTree(t, s.Config.SecurityDir)) {
		t.Fatal("native inventory read changed original configuration evidence")
	}
	t.Log("PASS actual complete six original configuration backups via authenticated Core and real Unix executor; fixed read-only metadata, no configuration bytes and no filesystem mutation")
	// Maintenance acts on a snapshot made by the actual lifecycle, after the
	// signed application was installed. No fabricated snapshot/receipt is used.
	original := inventory.Entries[0]
	originalPath := filepath.Join(s.Config.SecurityDir, "waf-backups", original.ID)
	originalDirectory, err := os.Lstat(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	securityRoot, err := os.OpenRoot(s.Config.SecurityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer securityRoot.Close()
	originalFiles, err := wafArchiveSnapshotIdentity(securityRoot, "waf-backups/"+original.ID)
	if err != nil {
		t.Fatal(err)
	}
	currentPaths := []string{s.Config.NginxConf, s.softwareManifestPath("nginx-waf"), filepath.Join(s.Config.ConfDir, selected.ID+".conf"), filepath.Join(s.Config.ConfDir, optedOut.ID+".conf")}
	h, v := wafFiles(s)
	currentPaths = append(currentPaths, h, v, s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf"), s.systemPath("/etc/panel/waf/body.d/"+selected.ID+".conf"))
	currentBefore := []fileBackup{}
	for _, path := range currentPaths {
		b, err := backupFile(path)
		if err != nil {
			t.Fatal(err)
		}
		currentBefore = append(currentBefore, b)
	}
	runnerMu.Lock()
	reloadsBeforeArchive := reloads
	runnerMu.Unlock()
	in := core.WAFBackupArchiveInput{ID: original.ID, SHA: original.SHA, Confirm: "ARCHIVE NGINX CONFIG " + original.ID}
	archiveBody, _ := json.Marshal(in)
	archivePath := "/api/software/nginx-waf/archive-config-backup"
	recoveryPath := "/api/software/nginx-waf/config-backup-archive-request"
	readRecovery := func(wantPending bool, actorCookie *http.Cookie) *core.WAFBackupArchivePending {
		t.Helper()
		before := wafInventoryTree(t, s.Config.SecurityDir)
		w := request("GET", recoveryPath, nil, "", "", actorCookie)
		var out core.WAFBackupArchiveRecovery
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.ReadOnly || (out.Pending != nil) != wantPending || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SecurityDir)) {
			t.Fatal("actual actor-bound read-only recovery", w.Code, w.Body.String())
		}
		for _, secret := range []string{"actor_id", "username", "request_audit_id", "confirm", "/etc/", "configuration"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("recovery leaked private fields", secret)
			}
		}
		if wantPending && (out.Pending.ID != in.ID || out.Pending.SHA != in.SHA || out.Pending.CreatedAt == "") {
			t.Fatal("actual recovery replaced original identity", out.Pending)
		}
		return out.Pending
	}
	readRecovery(false, cookie)
	for _, test := range []struct {
		path, csrf string
		cookie     *http.Cookie
		code       int
	}{{archivePath, "", cookie, 403}, {archivePath, auth.CSRF, nil, 401}, {archivePath + "?", auth.CSRF, cookie, 400}} {
		if w := request("POST", test.path, archiveBody, test.csrf, "", test.cookie); w.Code != test.code {
			t.Fatal("actual archive authorization/input", w.Code)
		}
	}
	endpointMu.Lock()
	if archiveMutations != 0 {
		t.Fatal("invalid archive reached native executor")
	}
	loseArchiveReply = true
	endpointMu.Unlock()
	w = request("POST", archivePath, archiveBody, auth.CSRF, "", cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"archived":true`) || !strings.Contains(w.Body.String(), "不宣称未移动") {
		t.Fatal("actual lost archive response falsely succeeded", w.Code, w.Body.String())
	}
	// All six queued lifecycle tasks are finished. Join ONLY this test's worker
	// before closing/reopening its actual private SQLite file; never race a DB
	// handle swap with a worker and never call this a cold boot or power loss.
	stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("own worker did not join before SQLite reopen")
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, reopenErr := core.OpenStore(filepath.Join(base, "data/panel.db"))
	if reopenErr != nil {
		t.Fatal(reopenErr)
	}
	store.DB = reopened.DB
	originalPending := readRecovery(true, cookie)
	if again := readOriginalDirectory(6, cookie); !reflect.DeepEqual(again, allOriginalRequests) {
		t.Fatal("actual original apply request lost after SQLite reopen")
	}
	for _, path := range []string{recoveryPath + "?", recoveryPath + "?actor_id=" + ownUser} {
		if w := request("GET", path, nil, "", "", cookie); w.Code != 400 {
			t.Fatal("recovery caller chose identity", w.Code)
		}
	}
	if w := request("GET", recoveryPath, nil, "", "", nil); w.Code != 401 {
		t.Fatal("anonymous pending recovery", w.Code)
	}
	otherID := core.ID()
	if _, err := store.DB.Exec(`INSERT INTO users SELECT ?,'nativeother',password_hash,created_at FROM users WHERE id=?`, otherID, ownUser); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'["runtimes","security"]',1)`, otherID); err != nil {
		t.Fatal(err)
	}
	otherLogin := request("POST", "/api/login", []byte(`{"username":"nativeother","password":"private-native-core-password-long"}`), "", "", nil)
	if otherLogin.Code != 200 || len(otherLogin.Result().Cookies()) != 1 {
		t.Fatal("other private actor login", otherLogin.Code)
	}
	readRecovery(false, otherLogin.Result().Cookies()[0])
	readOriginalDirectory(0, otherLogin.Result().Cookies()[0])
	if w := request("GET", "/api/software/nginx-waf/requests/"+installJob, nil, "", "", otherLogin.Result().Cookies()[0]); w.Code != 404 {
		t.Fatal("other actor inherited original signed install", w.Code)
	}
	archiveFullPath := filepath.Join(s.Config.SecurityDir, "waf-backup-archive", original.ID)
	afterDirectory, err := os.Lstat(archiveFullPath)
	if err != nil || !os.SameFile(originalDirectory, afterDirectory) || originalDirectory.Mode() != afterDirectory.Mode() {
		t.Fatal("actual lost response destroyed original directory identity", err)
	}
	afterFiles, err := wafArchiveSnapshotIdentity(securityRoot, "waf-backup-archive/"+original.ID)
	if err != nil || !reflect.DeepEqual(originalFiles, afterFiles) {
		t.Fatal("actual lost response changed original private bytes/identity", err)
	}
	if _, err := os.Lstat(originalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("actual handoff did not free one activity slot", err)
	}
	w = request("GET", "/api/software/nginx-waf/config-backup-archive/"+original.ID, nil, auth.CSRF, "", cookie)
	verifiedRow, err := core.DecodeWAFBackupSnapshot(w.Body.Bytes())
	if w.Code != 200 || err != nil || !reflect.DeepEqual(original, verifiedRow) {
		t.Fatal("actual original archived evidence cannot be independently verified", w.Code, err)
	}
	// A real SQLite audit failure follows the native original-identity replay.
	if _, err := store.DB.Exec(`CREATE TRIGGER refuse_owned_archive_confirmation BEFORE INSERT ON audit_logs WHEN NEW.action='waf.config-backup.archive-confirmed' BEGIN SELECT RAISE(ABORT,'owned native audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	beforeReplay := wafInventoryTree(t, s.Config.SecurityDir)
	w = request("POST", archivePath, archiveBody, auth.CSRF, "", cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"archived":true`) || !strings.Contains(w.Body.String(), "结果审计未保存") || !reflect.DeepEqual(beforeReplay, wafInventoryTree(t, s.Config.SecurityDir)) {
		t.Fatal("actual result audit failure falsely succeeded or altered archive", w.Code, w.Body.String())
	}
	if again := readRecovery(true, cookie); !reflect.DeepEqual(originalPending, again) {
		t.Fatal("audit failure replaced original pending identity", again)
	}
	if _, err := store.DB.Exec(`DROP TRIGGER refuse_owned_archive_confirmation`); err != nil {
		t.Fatal(err)
	}
	w = request("POST", archivePath, archiveBody, auth.CSRF, "", cookie)
	archiveReceipt, err := core.DecodeWAFBackupArchiveResult(w.Body.Bytes(), in)
	if w.Code != 200 || err != nil || !archiveReceipt.Replayed || !reflect.DeepEqual(beforeReplay, wafInventoryTree(t, s.Config.SecurityDir)) {
		t.Fatal("actual original replay changed evidence or failed to confirm", w.Code, err)
	}
	readRecovery(false, cookie)
	var requestAudits, confirmedAudits int
	if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-requested' AND target=?`, original.ID).Scan(&requestAudits); err != nil || requestAudits != 3 {
		t.Fatal(requestAudits, err)
	}
	if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-confirmed' AND target=?`, original.ID).Scan(&confirmedAudits); err != nil || confirmedAudits != 1 {
		t.Fatal(confirmedAudits, err)
	}
	for _, test := range []struct {
		path  string
		count int
	}{{"config-backups", 5}, {"config-backup-archive", 1}} {
		w := request("GET", "/api/software/nginx-waf/"+test.path, nil, auth.CSRF, "", cookie)
		out, err := core.DecodeWAFBackupInventory(w.Body.Bytes())
		if w.Code != 200 || err != nil || !out.Available || len(out.Entries) != test.count {
			t.Fatal("actual post-archive complete inventories", test.path, w.Code, err)
		}
	}
	for i, path := range currentPaths {
		actual, err := backupFile(path)
		if err != nil || !reflect.DeepEqual(actual, currentBefore[i]) {
			t.Fatal("actual archival altered live website/config/manifest", path, err)
		}
	}
	runnerMu.Lock()
	if reloads != reloadsBeforeArchive {
		t.Fatal("archival reloaded website")
	}
	runnerMu.Unlock()
	assertHTTP(200)
	verifyWAFProducedHTTPWorkers(t, master.Process.Pid, record.NginxBinary, 33)
	if row := registry(); !row.Installed || !row.Healthy || row.InstalledVersion != item.Version {
		t.Fatal("archival destroyed actual signed install receipt", row)
	}
	endpointMu.Lock()
	actualArchiveOperations := archiveMutations
	endpointMu.Unlock()
	if actualArchiveOperations != 3 {
		t.Fatal("actual archive attempt count", actualArchiveOperations)
	}
	archiveReport := map[string]any{"actual_original_snapshot_from_signed_lifecycle": true, "actual_original_directory_file_identity_retained": true, "actual_lost_executor_reply_stays_unknown": true, "actual_core_result_audit_failure_stays_unknown": true, "original_id_and_full_sha_replays_without_writes": true, "actual_requests": 3, "actual_moves": 1, "request_audits": requestAudits, "confirmed_audits": confirmedAudits, "active_snapshots_after": 5, "archived_snapshots_after": 1, "no_website_config_manifest_change_or_reload": true, "physical_disk_quota_verified": false, "power_loss_verified": false}
	archiveReport["actual_actor_bound_pending_survives_sqlite_close_reopen"] = true
	archiveReport["other_authenticated_actor_cannot_inherit_pending"] = true
	archiveReport["actual_result_audit_failure_retains_original_pending"] = true
	archiveReport["confirmed_audit_and_exact_ticket_closure_atomic"] = true
	t.Log("PASS actual original configuration archive via authenticated Core and real Unix executor; genuine snapshot, original bytes/inodes/mode/UID/GID retained; lost response and real SQLite audit failure unknown, same-ID/SHA replay, no website reload or policy change")
	t.Log("PASS actual actor-bound original archive request survives SQLite close/reopen; other authenticated actor sees no inherited pending identity; audit failure retains original ticket, explicit same-ID/SHA native replay confirms and closes it; no automatic executor recovery")
	t.Log("PASS actual current-actor original signed install and five configure requests read-only, complete original payload hashes/settings, queued request is not installed receipt; actual SQLite close/reopen retains all six identities; other actor has empty directory and original ID read 404; no new executor action or task")
	if err := moduleWrite(filepath.Join(base, "apply-request-acceptance.json"), map[string]any{"passed": true, "actual_original_apply_requests_actor_bound": true, "actual_original_apply_requests_count": 6, "actual_original_apply_requests_survive_sqlite_close_reopen": true, "actual_original_apply_requests_other_actor_no_inheritance": true, "actual_original_apply_requests_complete_payload_hash_and_settings": true, "queued_binding_is_not_installed_receipt": true, "read_only_no_new_executor_action_or_task": true, "cold_boot_verified": false, "browser_verified": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	endpointMu.Lock()
	actualMutations, actualPreFinish, excluded := mutations, preFinish, denied
	endpointMu.Unlock()
	runnerMu.Lock()
	actualReloads := reloads
	runnerMu.Unlock()
	if actualMutations != 6 || actualPreFinish != 1 || actualReloads < 8 || excluded == 0 {
		t.Fatal("native lifecycle coverage counts", actualMutations, actualPreFinish, actualReloads, excluded)
	}
	if authenticatedJobReads < 6 {
		t.Fatal("actual authenticated original task read coverage", authenticatedJobReads)
	}
	if marker.BrowserOrigin != "" {
		wafNativeBrowserWire(t, ctx, panel, store, base, panelOrigin, offJob)
		// A browser read must not mutate the native application or its live sites.
		for i, path := range currentPaths {
			actual, err := backupFile(path)
			if err != nil || !reflect.DeepEqual(actual, currentBefore[i]) {
				t.Fatal("browser altered live website/config/manifest", path, err)
			}
		}
		endpointMu.Lock()
		if mutations != actualMutations || archiveMutations != actualArchiveOperations {
			t.Fatal("browser created a new software executor write")
		}
		endpointMu.Unlock()
		assertHTTP(200)
		verifyWAFProducedHTTPWorkers(t, master.Process.Pid, record.NginxBinary, 33)
	}
	t.Logf("PASS authenticated original task API identity, target, kind, state and real Finish outcomes; reads=%d", authenticatedJobReads)
	t.Log("PASS actual WAF task API with software/security menus only; global audit 403 and wrong-WAF task 404; no extra executor capability")
	t.Log("PASS actual minimal WAF website API with software/security menus only; general sites 403; opt-out retained and wrong-webserver excluded; no extra executor capability")
	if err := moduleWrite(filepath.Join(base, "acceptance.json"), map[string]any{"passed": true, "actual_config_backup_archive": archiveReport, "genuine_job_id": id, "official_signed_catalog_default_key_verified": true, "genuine_package_sha256": manifestSHA, "offline_manifest_transport_not_live_github": true, "actual_authenticated_core_unix_executor_worker_sqlite_finish": true, "queued_and_pre_finish_have_no_install_receipt": true, "successful_signed_package_receipt": true, "immutable_queued_and_finished_install_and_configuration_replays": true, "exact_manifest_pulls": pulls, "actual_application_installed": true, "initial_website_creation_is_fixture_setup": true, "actual_explicit_single_site_body_block_observe_off": true, "opted_out_website_exact_bytes_preserved": true, "root_eb_actual_www_data_workers_c0_nnp": true, "failed_reload_and_false_ack_restore_bytes_mode_uid_gid": true, "existing_policy_and_engine_retained_when_disabled": true, "actual_metadata_and_authenticated_report": true, "actual_mutations": actualMutations, "actual_reloads": actualReloads, "excluded_capabilities_refused": excluded, "live_github_verified": false, "browser_accepted": false, "cold_boot_accepted": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual official signed-package install receipt only after authenticated Core / real Unix executor / actual worker / SQLite Finish; native one-site body block-observe-off and opt-out preservation; real failed/false-ack reload rollback and immutable replays; offline package transport, not live GitHub/browser/cold-boot/all-50 acceptance")
}
